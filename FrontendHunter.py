import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import os
import sys

# Tenta di importare il tuo backend
try:
    from FileHunter import FileHunter
except ImportError:
    messagebox.showerror("Errore", "FileHunter.py non trovato nella stessa cartella!")
    sys.exit(1)

# --- CONFIGURAZIONE VISIVA ---
ctk.set_appearance_mode("Dark")  # Modi: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Temi: "blue" (standard), "green", "dark-blue"

class ProfessionalHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Setup Finestra
        self.title("File Hunter Pro")
        self.geometry("800x600")
        self.resizable(False, False)
        
        # Inizializza il motore
        self.hunter = FileHunter()
        self.is_running = False

        # --- LAYOUT GUI ---
        self.create_interface()

    def create_interface(self):
        # 1. Header
        self.header_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.header_frame.pack(pady=20)
        
        ctk.CTkLabel(self.header_frame, text="File Hunter Pro", font=("Roboto Medium", 24)).pack()
        ctk.CTkLabel(self.header_frame, text="Automazione e Recupero Dati", font=("Roboto", 12), text_color="gray").pack()

        # 2. Main Container
        self.main_frame = ctk.CTkFrame(self, corner_radius=15)
        self.main_frame.pack(pady=10, padx=20, fill="both", expand=True)

        # --- SEZIONE INPUT ---
        self.grid_input(self.main_frame)

        # --- SEZIONE LOG & PROGRESS ---
        self.status_label = ctk.CTkLabel(self.main_frame, text="Pronto.", anchor="w")
        self.status_label.pack(fill="x", padx=20, pady=(20, 0))

        self.progressbar = ctk.CTkProgressBar(self.main_frame, height=15)
        self.progressbar.set(0)
        self.progressbar.pack(fill="x", padx=20, pady=5)

        # --- BOTTONE AVVIO ---
        self.btn_start = ctk.CTkButton(self, text="AVVIA ANALISI", 
                                     command=self.start_thread,
                                     height=50, 
                                     font=("Roboto Medium", 16),
                                     fg_color="#106A43", hover_color="#148052") # Verde professionale
        self.btn_start.pack(pady=20, padx=40, fill="x")

    def grid_input(self, parent):
        # Estensioni
        ctk.CTkLabel(parent, text="Estensioni da cercare (es. .pdf, .jpg)", font=("Arial", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 5))
        self.entry_ext = ctk.CTkEntry(parent, placeholder_text=".pdf, .docx, .png")
        self.entry_ext.pack(fill="x", padx=20)

        # Nome File (Fuzzing)
        ctk.CTkLabel(parent, text="Filtra per nome (Opzionale - Cerca anche simili)", font=("Arial", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 5))
        self.entry_name = ctk.CTkEntry(parent, placeholder_text="Es. 'fattura' troverà anche 'fttura_2023.pdf'")
        self.entry_name.pack(fill="x", padx=20)

        # Destinazione
        ctk.CTkLabel(parent, text="Cartella di Destinazione", font=("Arial", 12, "bold")).pack(anchor="w", padx=20, pady=(15, 5))
        dest_frame = ctk.CTkFrame(parent, fg_color="transparent")
        dest_frame.pack(fill="x", padx=20)
        
        self.btn_dest = ctk.CTkButton(dest_frame, text="Scegli Cartella", command=self.select_folder, width=120)
        self.btn_dest.pack(side="left")
        
        self.lbl_dest = ctk.CTkLabel(dest_frame, text="Nessuna cartella selezionata", text_color="gray")
        self.lbl_dest.pack(side="left", padx=10)
        self.selected_folder = ""

        # Opzioni Avanzate (Switch)
        opts_frame = ctk.CTkFrame(parent, fg_color="transparent")
        opts_frame.pack(fill="x", padx=20, pady=20)

        self.sw_mode = ctk.CTkSwitch(opts_frame, text="Sposta ed Elimina originali")
        self.sw_mode.pack(side="left", padx=(0, 20))
        
        self.sw_dedup = ctk.CTkSwitch(opts_frame, text="Evita Duplicati (Hash MD5)")
        self.sw_dedup.select()
        self.sw_dedup.pack(side="left", padx=20)
        
        self.sw_dry = ctk.CTkSwitch(opts_frame, text="Simulazione (Test)")
        self.sw_dry.pack(side="left", padx=20)

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.selected_folder = path
            self.lbl_dest.configure(text=f"...{path[-30:]}" if len(path) > 30 else path, text_color="white")

    def update_progress_safe(self, message, count):
        """Callback chiamata dal Backend"""
        # CustomTkinter è thread-safe per .configure, ma update_idletasks a volte serve
        self.status_label.configure(text=f"{message} (Totale: {count})")
        if self.is_running:
            self.progressbar.step() 

    def start_thread(self):
        if not self.entry_ext.get():
            messagebox.showwarning("Attenzione", "Inserisci almeno un'estensione!")
            return
        if not self.selected_folder:
            messagebox.showwarning("Attenzione", "Seleziona dove salvare i file!")
            return

        self.is_running = True
        self.btn_start.configure(state="disabled", text="ELABORAZIONE IN CORSO...")
        self.progressbar.start()
        
        threading.Thread(target=self.run_process, daemon=True).start()

    def run_process(self):
        try:
            estensioni = self.entry_ext.get().split(',')
            nome_query = self.entry_name.get().strip()
            mode = "move" if self.sw_mode.get() == 1 else "copy"
            
            # --- CHIAMATA AL BACKEND ---
            result = self.hunter.scan_and_process(
                estensioni_target=estensioni,
                cartella_destinazione=self.selected_folder,
                query_nome=nome_query if nome_query else None,
                mode=mode,
                deduplicate=bool(self.sw_dedup.get()),
                dry_run=bool(self.sw_dry.get()),
                progress_callback=self.update_progress_safe # Passiamo la funzione GUI
            )
            
            self.after(0, lambda: self.finish_process(result)) # Torna al thread principale per chiudere

        except Exception as e:
            self.after(0, lambda: self.finish_process({"status": "error", "message": str(e)}))

    def finish_process(self, result):
        self.is_running = False
        self.progressbar.stop()
        self.progressbar.set(1)
        self.btn_start.configure(state="normal", text="AVVIA ANALISI")
        
        if result["status"] == "success":
            dettagli = result.get('summary', {})
            msg = (f"Operazione Completata!\n\n"
                   f"File Trovati: {dettagli.get('files_trovati', result.get('trovati', 0))}\n"
                   f"Duplicati Evitati: {dettagli.get('files_duplicati', 0)}")
            messagebox.showinfo("Successo", msg)
            self.status_label.configure(text="Operazione completata con successo.")
        else:
            messagebox.showerror("Errore", result["message"])

if __name__ == "__main__":
    app = ProfessionalHunterApp()
    app.mainloop()