import tkinter as tk
from tkinter import ttk
import threading


class ProgramGUI(tk.Frame):
    def __init__(self):
        tk.Frame.__init__(self)
        self.master.title("VirusTotal File Scanner")
        self.master.minsize(height=100, width=300)
        self.master.resizable(width=tk.FALSE, height=tk.FALSE)
        self.grid(padx=10, pady=10)
        menubar = tk.Menu(self.master)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Exit", command=lambda: self.master.quit())
        menubar.add_cascade(label="File", menu=filemenu)
        self.master.config(menu=menubar)
        self.go_button = tk.Button(text='Run Scan')
        self.go_button.grid(row=0, column=0, padx=(10, 10), sticky="w")
        self.progress_bar = ttk.Progressbar(self, orient="horizontal",
                                            length=200, mode="determinate")
        self.progress_bar.grid(row=0, column=1, padx=(100, 10), sticky="ew")
        self.iterator_label = tk.Label()
        self.iterator_label.grid(row=1, column=0, padx=(10,10), sticky="w")
        self.file_label = tk.Label()
        self.file_label.grid(row=2, column=0, padx=(10, 10), sticky="w")