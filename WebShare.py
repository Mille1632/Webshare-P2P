import socket
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import select
import os
import hashlib
import struct
import snappy  # Snappy compression library

# Global variable to control the server loop
server_running = False

# Function to calculate checksum (MD5) of a file
def calculate_checksum(file_path):
    hash_md5 = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

# Function to automatically get the device's IP address
def get_device_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))  # Connect to an arbitrary IP (doesn't need to be reachable)
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# Function to compress a file before transfer using Snappy
def compress_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
        compressed_data = snappy.compress(data)  # Compress the file with Snappy
    return compressed_data

# Function to decompress a file after receiving using Snappy
def decompress_file(compressed_data, file_path):
    decompressed_data = snappy.uncompress(compressed_data)  # Decompress the file with Snappy
    with open(file_path, 'wb') as f:
        f.write(decompressed_data)

# Function to start the server to receive files
def start_peer_server(host, port, save_directory, progress_bar):
    global server_running
    server_running = True
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle's Algorithm
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Peer server listening on {host}:{port}")

    def handle_client_connection(client_socket, address):
        print(f"Connection established with {address}")
        with client_socket:
            file_path = filedialog.asksaveasfilename(initialdir=save_directory, title="Save Received File", defaultextension="")
            if file_path:
                # Receive the file size as raw bytes and unpack it
                file_size_data = client_socket.recv(4)  # We expect the file size to be a 4-byte integer
                if len(file_size_data) < 4:
                    print("Error receiving file size.")
                    return
                
                file_size = struct.unpack('!I', file_size_data)[0]  # Unpack 4 bytes as an unsigned integer
                print(f"Receiving file of size: {file_size} bytes")
                total_received = 0

                with open(file_path, 'wb') as f:
                    while server_running:
                        ready = select.select([client_socket], [], [], 2)
                        if ready[0]:
                            file_data = client_socket.recv(8192)  # Increased buffer size
                            if not file_data:
                                break
                            f.write(file_data)
                            total_received += len(file_data)

                            # Update progress bar based on total file size
                            if file_size > 0:  # Ensure division by zero is avoided
                                progress_bar["value"] = (total_received / file_size) * 100
                                progress_bar.update()

                print("File transfer completed")
                progress_bar.stop()
                messagebox.showinfo("File Transfer", "File transfer completed successfully")
            else:
                print("File saving was cancelled.")
        
        # Verify checksum after transfer
        try:
            received_checksum = client_socket.recv(1024).decode()
            if not received_checksum:
                print("Checksum not received or connection closed.")
                return

            calculated_checksum = calculate_checksum(file_path)
            if received_checksum == calculated_checksum:
                print("Checksum match: File integrity verified.")
            else:
                print("Checksum mismatch: File corrupted.")
        except OSError as e:
            print(f"Error receiving checksum: {e}")
            return
        
        # Properly close the socket
        try:
            client_socket.shutdown(socket.SHUT_RDWR)  # Close the connection after transfer
        except Exception as e:
            print(f"Error during socket shutdown: {e}")
        finally:
            client_socket.close()

    while server_running:
        try:
            client_socket, addr = server_socket.accept()
            threading.Thread(target=handle_client_connection, args=(client_socket, addr), daemon=True).start()
        except Exception as e:
            print(f"Server error: {e}")
            break
    server_socket.close()
    print("Server stopped")

# Function to stop the server
def stop_server():
    global server_running
    server_running = False
    messagebox.showinfo("Server", "Server stopped")

# Function to send a file to another peer
def send_file_to_peer(peer_ip, peer_port, file_path, progress_bar):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle's Algorithm
            client_socket.connect((peer_ip, peer_port))
            print(f"Connected to peer {peer_ip}:{peer_port}")
            compressed_data = compress_file(file_path)  # Compress the file using Snappy
            file_size = len(compressed_data)  # Get the compressed file size
            sent_bytes = 0

            # Send compressed file size as raw bytes (4 bytes)
            client_socket.sendall(struct.pack('!I', file_size))

            # Send the compressed file data
            while sent_bytes < file_size:
                chunk = compressed_data[sent_bytes:sent_bytes + 8192]  # Increased buffer size
                client_socket.sendall(chunk)
                sent_bytes += len(chunk)
                progress_bar["value"] = (sent_bytes / file_size) * 100  # Update progress bar based on total file size
                progress_bar.update()

            print("File sent successfully")

            # Send checksum for file integrity validation
            file_checksum = calculate_checksum(file_path)
            client_socket.sendall(file_checksum.encode())

            # Gracefully close the socket after transfer
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print(f"Error during socket shutdown: {e}")
            finally:
                client_socket.close()

            progress_bar.stop()
            messagebox.showinfo("File Transfer", "File sent successfully")
    except (socket.timeout, ConnectionRefusedError) as e:
        print(f"Failed to send file: {e}")
        progress_bar.stop()
        messagebox.showerror("File Transfer Error", f"Failed to send file: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        progress_bar.stop()
        messagebox.showerror("File Transfer Error", f"Unexpected error: {e}")

# GUI setup
def main_gui():
    def select_file():
        file_path = filedialog.askopenfilename()
        if file_path:
            entry_file_path.delete(0, tk.END)
            entry_file_path.insert(0, file_path)

    def select_save_directory():
        directory = filedialog.askdirectory()
        if directory:
            entry_save_directory.delete(0, tk.END)
            entry_save_directory.insert(0, directory)

    def start_server_thread():
        host = entry_host.get()
        port = int(entry_port.get())
        save_directory = entry_save_directory.get()
        threading.Thread(target=start_peer_server, args=(host, port, save_directory, progress_bar_receive), daemon=True).start()
        messagebox.showinfo("Server", f"Server started on {host}:{port}")

    def send_file():
        peer_ip = entry_peer_ip.get()
        peer_port = int(entry_peer_port.get())
        file_path = entry_file_path.get()
        if file_path:
            progress_bar_send.start()
            threading.Thread(target=send_file_to_peer, args=(peer_ip, peer_port, file_path, progress_bar_send), daemon=True).start()
        else:
            messagebox.showwarning("File Selection", "Please select a file to send.")

    def toggle_mode():
        if mode_var.get() == "Send Mode":
            mode_var.set("Receive Mode")
            frame_send.grid_remove()
            frame_receive.grid()
        else:
            mode_var.set("Send Mode")
            frame_receive.grid_remove()
            frame_send.grid()

    # Main window
    root = tk.Tk()
    root.title("WebShare - P2P Platform")

    mode_var = tk.StringVar(value="Send Mode")
    mode_button = tk.Button(root, textvariable=mode_var, command=toggle_mode)
    mode_button.grid(row=0, columnspan=2, pady=10)

    # Frame for server setup (Receive Mode)
    frame_receive = tk.Frame(root)
    tk.Label(frame_receive, text="Host:").grid(row=0, column=0, padx=5, pady=5)
    entry_host = tk.Entry(frame_receive)
    entry_host.grid(row=0, column=0, padx=5, pady=5)
    entry_host.insert(0, get_device_ip())  # Set host to device's IP

    tk.Label(frame_receive, text="Port:").grid(row=1, column=0, padx=5, pady=5)
    entry_port = tk.Entry(frame_receive)
    entry_port.grid(row=1, column=0, padx=5, pady=5)
    entry_port.insert(0, "12345")

    tk.Label(frame_receive, text="Save Directory:").grid(row=2, column=0, padx=5, pady=5)
    entry_save_directory = tk.Entry(frame_receive, width=40)
    entry_save_directory.grid(row=2, column=0, padx=5, pady=5)

    btn_select_save_directory = tk.Button(frame_receive, text="Select Directory", command=select_save_directory)
    btn_select_save_directory.grid(row=2, column=1, padx=5, pady=5)

    btn_start_server = tk.Button(frame_receive, text="Start Server", command=start_server_thread)
    btn_start_server.grid(row=3, column=1, padx=5, pady=5)

    btn_stop_server = tk.Button(frame_receive, text="Stop Server", command=stop_server)
    btn_stop_server.grid(row=4, column=1, padx=5, pady=5)

    progress_bar_receive = ttk.Progressbar(frame_receive, orient="horizontal", mode="determinate", length=300)
    progress_bar_receive.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    # Frame for file selection and sending (Send Mode)
    frame_send = tk.Frame(root)
    tk.Label(frame_send, text="Peer IP:").grid(row=0, column=0, padx=5, pady=5)
    entry_peer_ip = tk.Entry(frame_send)
    entry_peer_ip.grid(row=0, column=0, padx=5, pady=5)
    entry_peer_ip.insert(0, "127.0.0.1")

    tk.Label(frame_send, text="Peer Port:").grid(row=1, column=0, padx=5, pady=5)
    entry_peer_port = tk.Entry(frame_send)
    entry_peer_port.grid(row=1, column=0, padx=5, pady=5)
    entry_peer_port.insert(0, "12345")

    tk.Label(frame_send, text="File Path:").grid(row=2, column=0, padx=5, pady=5)
    entry_file_path = tk.Entry(frame_send, width=40)
    entry_file_path.grid(row=2, column=0, padx=5, pady=5)

    btn_select_file = tk.Button(frame_send, text="Select File", command=select_file)
    btn_select_file.grid(row=2, column=1, padx=5, pady=5)

    btn_send_file = tk.Button(frame_send, text="Send File", command=send_file)
    btn_send_file.grid(row=3, column=1, padx=5, pady=5)

    progress_bar_send = ttk.Progressbar(frame_send, orient="horizontal", mode="determinate", length=300)
    progress_bar_send.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

    frame_send.grid(row=1, column=0, columnspan=2)
    frame_receive.grid(row=1, column=0, columnspan=2)
    frame_receive.grid_remove()

    root.mainloop()

if __name__ == "__main__":
    main_gui()
