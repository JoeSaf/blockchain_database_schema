import tkinter as tk
from tkinter import filedialog, ttk
import os
from datetime import datetime

class FileUploadDialog:
    def __init__(self, parent=None, title="File Upload"):
        self.selected_files = []
        self.result = None
        self.dialog_closed = False
        
        # Create the main window
        self.root = tk.Tk() if parent is None else tk.Toplevel(parent)
        self.root.title(title)
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.cancel)  # Handle window close button
        
        # Make the window modal
        self.root.transient(parent if parent else None)
        self.root.grab_set()
        
        # Create and configure the main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Create a frame for file list and details
        list_frame = ttk.LabelFrame(main_frame, text="Selected Files", padding="5")
        list_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Create the file list with columns
        columns = ('filename', 'size', 'type', 'modified')
        self.file_list = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Define headings
        self.file_list.heading('filename', text='Filename')
        self.file_list.heading('size', text='Size')
        self.file_list.heading('type', text='Type')
        self.file_list.heading('modified', text='Modified')
        
        # Define columns
        self.file_list.column('filename', width=300)
        self.file_list.column('size', width=100)
        self.file_list.column('type', width=100)
        self.file_list.column('modified', width=150)
        
        # Add scrollbar to file list
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_list.yview)
        self.file_list.configure(yscrollcommand=scrollbar.set)
        
        # Grid the file list and scrollbar
        self.file_list.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Create buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Create buttons
        ttk.Button(button_frame, text="Add Files", command=self.add_files).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Clear All", command=self.clear_all).grid(row=0, column=2, padx=5)
        
        # Create confirm and cancel buttons
        ttk.Button(button_frame, text="Confirm", command=self.confirm).grid(row=0, column=3, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel).grid(row=0, column=4, padx=5)
        
        # Add status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Center the window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
    def format_size(self, size_bytes):
        """Convert size in bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
    
    def get_file_info(self, file_path):
        """Get file information for display"""
        try:
            stat = os.stat(file_path)
            size = self.format_size(stat.st_size)
            file_type = os.path.splitext(file_path)[1][1:].upper() or 'File'
            modified = datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            return size, file_type, modified
        except Exception:
            return "Unknown", "Unknown", "Unknown"
    
    def add_files(self):
        if self.dialog_closed:
            return
            
        files = filedialog.askopenfilenames(
            title="Select Files",
            filetypes=[
                ("All Files", "*.*"),
                ("Text Files", "*.txt"),
                ("JSON Files", "*.json"),
                ("Python Files", "*.py"),
                ("Image Files", "*.png *.jpg *.jpeg *.gif"),
                ("Document Files", "*.pdf *.doc *.docx")
            ]
        )
        for file in files:
            if file not in self.selected_files:
                self.selected_files.append(file)
                size, file_type, modified = self.get_file_info(file)
                self.file_list.insert('', 'end', values=(
                    os.path.basename(file),
                    size,
                    file_type,
                    modified
                ))
        self.update_status()
    
    def remove_selected(self):
        if self.dialog_closed:
            return
            
        selected = self.file_list.selection()
        for item in selected:
            index = self.file_list.index(item)
            self.file_list.delete(item)
            self.selected_files.pop(index)
        self.update_status()
    
    def clear_all(self):
        if self.dialog_closed:
            return
            
        self.file_list.delete(*self.file_list.get_children())
        self.selected_files.clear()
        self.update_status()
    
    def update_status(self):
        if self.dialog_closed:
            return
            
        total_size = sum(os.path.getsize(f) for f in self.selected_files)
        self.status_var.set(f"Selected {len(self.selected_files)} files ({self.format_size(total_size)})")
    
    def confirm(self):
        if self.dialog_closed:
            return
            
        self.result = self.selected_files.copy()
        self.dialog_closed = True
        self.root.grab_release()
        self.root.quit()
        self.root.destroy()
    
    def cancel(self):
        if self.dialog_closed:
            return
            
        self.result = None
        self.dialog_closed = True
        self.root.grab_release()
        self.root.quit()
        self.root.destroy()
    
    def show(self):
        self.root.mainloop()
        return self.result 