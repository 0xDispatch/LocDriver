import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct

class StringTableEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("String Table Editor")
        self.root.geometry("800x600")
        
        self.original_data = None
        self.strings = []
        self.string_offsets = []
        
        self.create_ui()

    def create_ui(self):
        # Top frame for buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill='x', padx=5, pady=5)
        
        ttk.Button(button_frame, text="Load File", command=self.load_file).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Save File", command=self.save_file).pack(side='left', padx=5)
        
        # Search frame
        search_frame = ttk.Frame(self.root)
        search_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(search_frame, text="Search:").pack(side='left', padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_strings)
        ttk.Entry(search_frame, textvariable=self.search_var).pack(side='left', fill='x', expand=True)
        
        # Create treeview for strings
        self.tree = ttk.Treeview(self.root, columns=('Index', 'Offset', 'Length', 'String'), show='headings')
        self.tree.heading('Index', text='Index')
        self.tree.heading('Offset', text='Offset')
        self.tree.heading('Length', text='Length')
        self.tree.heading('String', text='String')
        self.tree.column('Index', width=50)
        self.tree.column('Offset', width=100)
        self.tree.column('Length', width=100)
        self.tree.column('String', width=600)
        self.tree.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.root, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind double-click event
        self.tree.bind('<Double-1>', self.edit_string)

    def find_string_table_header(self, data):
        """Parse CHNK format and store section offsets"""
        try:
            sections = {}
            for pattern in [b'SLRR', b'SLRH', b'SLRC', b'SLRS']:
                try:
                    pos = data.index(pattern)
                    size = struct.unpack('<I', data[pos+4:pos+8])[0]
                    sections[pattern] = (pos, size)
                    print(f"Found {pattern} at 0x{pos:X}, size: {size}")
                except ValueError:
                    continue
                    
            if b'SLRH' not in sections or b'SLRC' not in sections or b'SLRS' not in sections:
                raise ValueError("Missing required sections")
            
            # Store section offsets as class attributes
            self.slrh_offset, _ = sections[b'SLRH']
            self.slrc_offset, _ = sections[b'SLRC']
            self.slrs_offset, _ = sections[b'SLRS']
            
            # Read string count from SLRH
            string_count = struct.unpack('<I', data[self.slrh_offset+8:self.slrh_offset+12])[0]
            print(f"\nString count from SLRH: {string_count}")
            
            # Store string count
            self.string_count = string_count
            
            # Calculate table start
            table_start = self.slrc_offset + 8  # Skip section header
            print(f"Found table_start at: 0x{table_start:X}")
            
            return table_start

        except Exception as e:
            print(f"Detailed error: {str(e)}")
            raise

    def read_string_table(self, data):
        """Read strings using lookup table and string data"""
        try:
            result_strings = []
            string_offsets = []
            processed_offsets = set()
            
            print("\nReading string table:")
            print(f"SLRC offset: 0x{self.slrc_offset:X}")
            print(f"SLRS offset: 0x{self.slrs_offset:X}")
            print(f"SLRS size: {len(data) - self.slrs_offset}")
            
            def hex_dump(offset, length):
                bytes_data = data[offset:offset+length]
                hex_str = ' '.join(f'{b:02X}' for b in bytes_data)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in bytes_data)
                return f"Hex: {hex_str}\nASCII: {ascii_str}"
            
            def is_valid_string(s):
                """Check if string appears to be valid text"""
                if not s or len(s) < 2:
                    return False
                
                # Check for common text characteristics
                text_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,!?-_\'\" ')
                non_text = 0
                
                for c in s:
                    if c not in text_chars:
                        non_text += 1
                    
                # Allow up to 20% non-text characters
                return (non_text / len(s)) < 0.2
            
            def find_string_boundaries(offset):
                """Find the start and end of a complete string"""
                # Look backwards for start of string (previous 00 00)
                start = offset
                while start > self.slrs_offset:
                    if data[start-2] == 0 and data[start-1] == 0:
                        break
                    start -= 2
                
                # Look forward for end of string (next 00 00)
                end = offset
                while end < len(data) - 1:
                    if data[end] == 0 and data[end + 1] == 0:
                        break
                    end += 2
                    
                return start, end
            
            def try_read_string(offset):
                """Try to read a string at the given offset"""
                if offset in processed_offsets:
                    return None, None
                    
                try:
                    # Find complete string boundaries
                    start, end = find_string_boundaries(offset)
                    if start >= end or end - start > 2048:  # Safety limit
                        return None, None
                    
                    # Extract and decode string
                    string_bytes = data[start:end]
                    if string_bytes:
                        try:
                            string = bytes(string_bytes).decode('utf-16-le').strip()
                            if string and is_valid_string(string):
                                # Mark all offsets in this string as processed
                                for i in range(start, end, 2):
                                    processed_offsets.add(i)
                                return string, start
                        except:
                            pass
                except:
                    pass
                return None, None
            
            # Scan SLRS section for strings
            print("\nScanning SLRS section for strings...")
            current_offset = self.slrs_offset
            last_progress = 0
            
            while current_offset < len(data) - 2:
                # Show progress every 1%
                progress = int((current_offset - self.slrs_offset) * 100 / (len(data) - self.slrs_offset))
                if progress > last_progress:
                    print(f"Progress: {progress}%")
                    last_progress = progress
                
                string, start_offset = try_read_string(current_offset)
                if string and start_offset == current_offset:  # Only process strings at their start
                    print(f"\nFound string at 0x{current_offset:X}:")
                    print(hex_dump(current_offset, min(32, len(data) - current_offset)))
                    print(f"String: {string}")
                    result_strings.append((len(result_strings), string))
                    string_offsets.append(current_offset)
                
                current_offset += 2
            
            print(f"\nSuccessfully read {len(result_strings)} strings")
            return result_strings, string_offsets
            
        except Exception as e:
            print(f"Error reading string table: {str(e)}")
            raise

    def load_file(self):
        filename = filedialog.askopenfilename(filetypes=[("FCHUNK files", "*.fchunk"), ("All files", "*.*")])
        if not filename:
            return
            
        try:
            with open(filename, 'rb') as f:
                self.original_data = f.read()
            
            print(f"File size: {len(self.original_data)} bytes")
            
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Find string table header
            table_start = self.find_string_table_header(self.original_data)
            if table_start is None:
                raise Exception("Could not find string table header")
            
            print(f"Found table_start at: {hex(table_start)}")
            
            # Read strings and offsets
            self.strings, self.string_offsets = self.read_string_table(self.original_data)
            
            # Populate treeview
            for idx, (string, offset) in enumerate(zip(self.strings, self.string_offsets)):
                length = (len(string) * 2) + 2
                self.tree.insert('', 'end', values=(idx, hex(offset), length, string))
            
            messagebox.showinfo("Success", f"Loaded {len(self.strings)} strings")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            print(f"Detailed error: {str(e)}")

    def filter_strings(self, *args):
        search_term = self.search_var.get().lower()
        
        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Repopulate with filtered items
        for idx, (string, offset) in enumerate(zip(self.strings, self.string_offsets)):
            if search_term in string.lower():
                self.tree.insert('', 'end', values=(idx, hex(offset), string))

    def edit_string(self, event):
        selection = self.tree.selection()
        if not selection:
            return
            
        item = selection[0]
        idx = int(self.tree.item(item)['values'][0])  # Get original index
        
        # Create edit dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit String")
        dialog.geometry("600x200")
        
        # Add text entry
        text_var = tk.StringVar(value=self.strings[idx])
        entry = ttk.Entry(dialog, textvariable=text_var, width=70)
        entry.pack(padx=10, pady=10)
        
        def save_changes():
            new_text = text_var.get()
            self.strings[idx] = new_text
            self.tree.set(item, 'String', new_text)
            dialog.destroy()
            
        ttk.Button(dialog, text="Save", command=save_changes).pack(pady=5)
        ttk.Button(dialog, text="Cancel", command=dialog.destroy).pack(pady=5)

    def save_file(self):
        if not self.original_data:
            messagebox.showerror("Error", "No file loaded")
            return
            
        filename = filedialog.asksaveasfilename(
            defaultextension=".fchunk",
            filetypes=[("FCHUNK files", "*.fchunk"), ("All files", "*.*")]
        )
        if not filename:
            return
            
        try:
            # Create new data with modified strings
            new_data = bytearray(self.original_data)
            
            # Replace each string at its offset
            for string, offset in zip(self.strings, self.string_offsets):
                # Convert string to UTF-16 bytes
                string_bytes = string.encode('utf-16-le')
                # Write the string at its offset
                for i, b in enumerate(string_bytes):
                    if offset + i < len(new_data):
                        new_data[offset + i] = b
            
            # Write the modified data
            with open(filename, 'wb') as f:
                f.write(new_data)
                
            messagebox.showinfo("Success", "File saved successfully")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = StringTableEditor(root)
    root.mainloop()
