import json
import os
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog, ttk
import pyperclip  #clipboard functionality

# Hardcoded Fernet key for wallet encryption (make sure it's kept secret)
# use a fernet-ket generator to replace this example
FERNET_KEY = b'9gkd1J2opw8MI2-5GHcd-yqYc_zOTwDHRBPiFdE8oYM='

# Initialize wallet management
wallets = {}

def encrypt_data(data):
    fernet = Fernet(FERNET_KEY)
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data):
    fernet = Fernet(FERNET_KEY)
    return fernet.decrypt(data.encode()).decode()

def load_wallets(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as file:
            encrypted_data = file.read()
            decrypted_data = decrypt_data(encrypted_data)
            return json.loads(decrypted_data)  # Load the JSON data
    return {"passwords": [], "mainkey": ""}

def save_wallets(filename, wallets):
    encrypted_data = encrypt_data(json.dumps(wallets))
    with open(filename, 'w') as file:
        file.write(encrypted_data)

class WalletManager(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Wallet Manager")
        self.geometry("1200x500")
        self.current_wallet = None
        self.filename = None

        # Create menu
        self.create_menu()
        
        # Create Treeview for displaying wallet contents
        self.create_treeview()

        # Set up a search entry
        self.create_search()

        # Context menu for editing records
        self.create_context_menu()


    def create_menu(self):
        menu = tk.Menu(self)
        self.config(menu=menu)

        file_menu = tk.Menu(menu)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Wallet", command=self.create_new_wallet)
        file_menu.add_command(label="Open Wallet", command=self.open_wallet)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        edit_menu = tk.Menu(menu)
        menu.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Add Password", command=self.add_password)

        export_menu = tk.Menu(menu)
        menu.add_cascade(label="Export", menu=export_menu)
        export_menu.add_command(label="Export Wallet", command=self.export_wallet)

    def create_treeview(self):
        self.tree = ttk.Treeview(self, columns=("Site URL", "Site Name", "User Nickname", "User Connection", "User Password", "Comment"), show="headings")
        self.tree.heading("Site URL", text="Site URL")
        self.tree.heading("Site Name", text="Site Name")
        self.tree.heading("User Nickname", text="User Nickname")
        self.tree.heading("User Connection", text="User Connection")
        self.tree.heading("User Password", text="User Password")
        self.tree.heading("Comment", text="Comment")
        self.tree.pack(expand=True, fill=tk.BOTH)

        # Binding the selection event to enable actions based on selection
        self.tree.bind("<ButtonRelease-1>", self.on_tree_select)

    def create_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Edit User Nickname", command=self.edit_nickname)
        self.context_menu.add_command(label="Edit User Connection", command=self.edit_connection)
        self.context_menu.add_command(label="Edit User Password", command=self.edit_password)
        self.context_menu.add_command(label="Edit Comment", command=self.edit_comment)

        self.tree.bind("<Button-3>", self.show_context_menu)  # Right-click event

    def show_context_menu(self, event):
        self.tree.selection_set(self.tree.identify_row(event.y))  # Select the row where the right-click occurred
        self.context_menu.post(event.x_root, event.y_root)  # Display the context menu


    def create_search(self):
        search_frame = tk.Frame(self)
        search_frame.pack()

        # Display the wallet name next to the search
        self.wallet_name_label = tk.Label(search_frame, text="No wallet opened", width=30, anchor="w")
        self.wallet_name_label.grid(row=0, column=0, padx=5)

        tk.Label(search_frame, text="Search:").grid(row=0, column=1)
        self.search_entry = tk.Entry(search_frame)
        self.search_entry.grid(row=0, column=2)
        
        tk.Button(search_frame, text="Search", command=self.search_password).grid(row=0, column=3)
        tk.Button(search_frame, text="Copy Connection", command=self.copy_user_connection, bg="green").grid(row=0, column=4)
        tk.Button(search_frame, text="Copy Password", command=self.copy_user_password, bg="green").grid(row=0, column=5)

    def create_new_wallet(self):
        wallet_name = filedialog.asksaveasfilename(defaultextension=".paz", filetypes=[("Wallet Files", "*.paz")])
        if wallet_name:
            mainkey = simpledialog.askstring("Main Key", "Enter a password to protect this wallet (mainkey):")
            if mainkey:
                new_wallet = {"passwords": [], "mainkey": mainkey}
                save_wallets(wallet_name, new_wallet)
                messagebox.showinfo("Success", "New wallet created successfully!")
                self.filename = wallet_name
                self.load_wallet()

    def open_wallet(self):
        self.filename = filedialog.askopenfilename(filetypes=[("Wallet Files", "*.paz")])
        if self.filename:
            mainkey = simpledialog.askstring("Main Key", "Enter the wallet password (mainkey) to open:")
            if mainkey:
                global wallets
                wallet_data = load_wallets(self.filename)
                if wallet_data["mainkey"] == mainkey:
                    self.current_wallet = wallet_data
                    self.load_wallet()
                    self.update_window_title()  # Update title with the wallet name
                    self.wallet_name_label.config(text=os.path.basename(self.filename))  # Display wallet name
                else:
                    messagebox.showerror("Error", "Incorrect password. Wallet cannot be opened.")

    def load_wallet(self):
        self.tree.delete(*self.tree.get_children())
        if self.current_wallet:
            for entry in self.current_wallet["passwords"]:
                self.tree.insert("", "end", values=(entry['site_url'], entry['site_name'], entry.get('user_nickname', ''), entry['user_connection'], entry['user_password'], entry['comment']))


    def update_window_title(self):
        if self.filename:
            self.title(f"Wallet Manager - {os.path.basename(self.filename)}")  # Show the opened wallet name in the title

    def add_password(self):
        if self.current_wallet is None:
            messagebox.showwarning("Warning", "Please open a wallet first.")
            return

        site_url = simpledialog.askstring("Site URL", "Enter Site URL:")
        site_name = simpledialog.askstring("Site Name", "Enter Site Name:")
        user_connection = simpledialog.askstring("User Connection", "Enter User Connection:")
        user_nickname = simpledialog.askstring("User Nickname (optional)", "Enter User Nickname (Optional):")  # Optional nickname
        user_password = simpledialog.askstring("User Password", "Enter User Password:")
        comment = simpledialog.askstring("Comment", "Enter Comment (Optional):")  # Allow empty comment

        if site_url and site_name and user_connection and user_password:
            self.current_wallet["passwords"].append({
                'site_url': site_url,
                'site_name': site_name,
                'user_connection': user_connection,
                'user_nickname': user_nickname or '',  # Default to empty if not provided
                'user_password': user_password,
                'comment': comment or ''  # Default to empty if not provided
            })
            save_wallets(self.filename, self.current_wallet)
            self.load_wallet()
            messagebox.showinfo("Success", "Password added successfully!")
        else:
            messagebox.showwarning("Warning", "Please fill in all required fields.")

    def search_password(self):
        search_term = self.search_entry.get()
        self.tree.delete(*self.tree.get_children())

        if self.current_wallet:
            found = False
            for entry in self.current_wallet["passwords"]:
                if (search_term.lower() in entry['site_url'].lower() or 
                    search_term.lower() in entry['site_name'].lower()):
                    found = True
                    self.tree.insert("", "end", values=(entry['site_url'], entry['site_name'], entry.get('user_nickname', ''), entry['user_connection'], entry['user_password'], entry['comment']))
            if not found:
                messagebox.showinfo("Info", "No matching entries found.")

    def on_tree_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            self.selected_entry = self.tree.item(selected_item)
        else:
            self.selected_entry = None

    def copy_user_connection(self):
        if self.selected_entry:
            user_connection = self.selected_entry['values'][3]  # User Connection
            pyperclip.copy(user_connection)
            messagebox.showinfo("Copied!", "User connection copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No entry selected.")


    def copy_user_password(self):
        if self.selected_entry:
            user_password = self.selected_entry['values'][4]  # User Password
            pyperclip.copy(user_password)
            messagebox.showinfo("Copied!", "User password copied to clipboard.")
        else:
            messagebox.showwarning("Warning", "No entry selected.")

    def edit_nickname(self):
        if self.selected_entry:
            new_nickname = simpledialog.askstring("Edit User Nickname", "Enter new User Nickname:", initialvalue=self.selected_entry['values'][2])
            if new_nickname is not None:
                self.selected_entry['values'][2] = new_nickname
                self.update_record()
        else:
            messagebox.showwarning("Warning", "No entry selected.")

    def edit_connection(self):
        if self.selected_entry:
            new_connection = simpledialog.askstring("Edit User Connection", "Enter new User Connection:", initialvalue=self.selected_entry['values'][3])
            if new_connection is not None:
                self.selected_entry['values'][3] = new_connection
                self.update_record()
        else:
            messagebox.showwarning("Warning", "No entry selected.")

    def edit_password(self):
        if self.selected_entry:
            new_password = simpledialog.askstring("Edit User Password", "Enter new User Password:", initialvalue=self.selected_entry['values'][4])
            if new_password is not None:
                self.selected_entry['values'][4] = new_password
                self.update_record()
        else:
            messagebox.showwarning("Warning", "No entry selected.")


    def edit_comment(self):
        if self.selected_entry:
            new_comment = simpledialog.askstring("Edit Comment", "Enter new Comment:", initialvalue=self.selected_entry['values'][5])
            if new_comment is not None:
                self.selected_entry['values'][5] = new_comment
                self.update_record()
        else:
            messagebox.showwarning("Warning", "No entry selected.")

    def update_record(self):
        if self.current_wallet and self.selected_entry:
            # Update the original wallets list
            site_url, site_name = self.selected_entry['values'][0:2]
            for entry in self.current_wallet["passwords"]:
                if entry['site_url'] == site_url and entry['site_name'] == site_name:
                    entry['user_nickname'] = self.selected_entry['values'][2]
                    entry['user_connection'] = self.selected_entry['values'][3]
                    entry['user_password'] = self.selected_entry['values'][4]
                    entry['comment'] = self.selected_entry['values'][5]
                    save_wallets(self.filename, self.current_wallet)
                    break
            self.load_wallet()
        
    def export_wallet(self):
        if self.current_wallet is None:
            messagebox.showwarning("Warning", "Please open a wallet first.")
            return
        export_file = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if export_file:
            with open(export_file, 'w') as file:
                json.dump(self.current_wallet, file, indent=4)
            messagebox.showinfo("Success", f"Wallet data exported to {export_file} successfully!")

if __name__ == "__main__":
    app = WalletManager()
    app.mainloop()
