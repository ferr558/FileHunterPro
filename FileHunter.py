import os
import shutil
import platform
import difflib
import hashlib
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

# --- CONFIGURAZIONE SICUREZZA ---
# Cartelle da ignorare TASSATIVAMENTE per evitare di rompere il PC o loop infiniti
SKIP_DIRS = {
    # Windows
    'Windows', 'Program Files', 'Program Files (x86)', 'System Volume Information', '$RECYCLE.BIN',
    # Linux / Mac
    'proc', 'sys', 'dev', 'run', 'boot', 'bin', 'sbin', 'lib', 'usr', 'Applications'
}

class FileHunter:
    def __init__(self):
        self.os_type = platform.system()
        # Tracking per evitare duplicati basati su hash
        self.processed_hashes = set()
        # Log dettagliato per report
        self.scan_log = []
        
    def get_root_dirs(self):
        """Restituisce le root da scansionare in base al sistema operativo."""
        roots = []
        if self.os_type == 'Windows':
            # Trova tutti i drive disponibili (C:\, D:\, E:\...)
            import string
            drives = [f'{d}:\\' for d in string.ascii_uppercase if os.path.exists(f'{d}:\\')]
            roots = drives
        else:
            # Linux e Mac partono da /
            # Nota: Scan da /home/ è più sicuro e veloce, ma l'utente ha chiesto root.
            # Per sicurezza in vendita, suggerirei di partire da os.path.expanduser("~")
            # Ma qui implementiamo la logica richiesta (Root)
            roots = ['/'] 
        return roots

    def fuzzy_match(self, nome_file_reale, query_utente):
        """
        Logica di Fuzzing Intelligente.
        Restituisce True se il nome file assomiglia a quello cercato dall'utente.
        """
        if not query_utente:
            return True # Se l'utente non cerca un nome, va bene tutto
        
        nome_reale_clean = nome_file_reale.lower()
        query_clean = query_utente.lower()

        # 1. Match Esatto o Parziale (Contiene la stringa)
        if query_clean in nome_reale_clean:
            return True
        
        # 2. Match Probabilistico (Fuzzing)
        # Ratio > 0.6 significa "simile al 60%" (es. "fattura" trova "fttura")
        ratio = difflib.SequenceMatcher(None, query_clean, nome_reale_clean).ratio()
        return ratio > 0.65

    def calculate_file_hash(self, filepath: Path, chunk_size: int = 8192) -> str:
        """
        [FEATURE 2] Calcola hash MD5 del file per identificare duplicati identici.
        Legge il file a blocchi per gestire file grandi senza saturare la RAM.
        """
        hash_md5 = hashlib.md5()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except Exception:
            # Se non riesco a leggere il file, restituisco un hash "unico" basato sul path
            # Così non viene considerato duplicato ma non blocca lo scan
            return f"error_{filepath}"

    def check_size_filter(self, file_size: int, min_size: Optional[int], max_size: Optional[int]) -> bool:
        """
        [FEATURE 4] Filtro per dimensione file (in bytes).
        """
        if min_size is not None and file_size < min_size:
            return False
        if max_size is not None and file_size > max_size:
            return False
        return True

    def check_date_filter(self, file_mtime: float, date_from: Optional[datetime], date_to: Optional[datetime]) -> bool:
        """
        [FEATURE 4] Filtro per data modifica file.
        """
        file_datetime = datetime.fromtimestamp(file_mtime)
        if date_from is not None and file_datetime < date_from:
            return False
        if date_to is not None and file_datetime > date_to:
            return False
        return True

    def format_size(self, size_bytes: int) -> str:
        """Helper per convertire bytes in formato leggibile (KB, MB, GB)."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def update_progress(self, current: int, total: int, file_name: str):
        """
        [FEATURE 3] Progress indicator semplice (senza librerie esterne).
        Mostra progresso ogni N file per non intasare il terminale.
        """
        if total > 0 and current % max(1, total // 20) == 0:  # Aggiorna ogni 5%
            percentage = (current / total) * 100
            print(f"[{percentage:.1f}%] Analizzati {current}/{total} file... ({file_name})")

    def scan_and_process(self, 
                        estensioni_target: List[str], 
                        cartella_destinazione: str, 
                        query_nome: Optional[str] = None, 
                        mode: str = "copy",
                        # --- NUOVI PARAMETRI OPZIONALI (retrocompatibili) ---
                        deduplicate: bool = True,           # [FEATURE 2] Hash deduplication
                        min_size: Optional[int] = None,     # [FEATURE 4] Dimensione minima (bytes)
                        max_size: Optional[int] = None,     # [FEATURE 4] Dimensione massima (bytes)
                        date_from: Optional[datetime] = None,  # [FEATURE 4] Data modifica da
                        date_to: Optional[datetime] = None,    # [FEATURE 4] Data modifica a
                        dry_run: bool = False,              # [FEATURE 5] Modalità anteprima
                        generate_report: bool = False,      # [FEATURE 5] Genera report JSON
                        show_progress: bool = True,  
                        progress_callback = None        # [FEATURE 3] Mostra progress
                        ) -> Dict[str, Any]:
        """
        Motore principale MIGLIORATO.
        
        RETROCOMPATIBILITÀ GARANTITA:
        - Vecchia chiamata: scan_and_process(['.jpg'], '/dest', 'foto', 'copy')
        - Funziona identicamente a prima!
        
        NUOVE FEATURES (tutte opzionali):
        - deduplicate: Evita di copiare file identici (stesso hash)
        - min_size/max_size: Filtra per dimensione file
        - date_from/date_to: Filtra per data modifica
        - dry_run: Modalità anteprima (non copia/sposta)
        - generate_report: Salva report JSON dettagliato
        - show_progress: Mostra progress bar testuale
        """
        # Reset tracking per nuova scansione
        self.processed_hashes.clear()
        self.scan_log.clear()
        
        roots = self.get_root_dirs()
        estensioni_target = [e.lower().strip() for e in estensioni_target]
        
        files_trovati = 0
        files_duplicati = 0
        files_filtrati = 0
        files_errori = 0
        dest_folder_skipped = 0  # ✅ Conta quante volte skippiamo la destinazione
        total_size = 0
        
        path_dest = Path(cartella_destinazione)
        if not dry_run:
            path_dest.mkdir(parents=True, exist_ok=True)
        
        # ✅ FIX ANTI-OUROBOROS: Risolve path assoluto della destinazione
        # Questo previene il loop dove il programma scansiona i file appena copiati
        # Dimezza il tempo di scan evitando di leggere/hashare file già processati
        dest_absolute = path_dest.resolve()
        print(f"🚫 Anti-Ouroboros: Salterò la cartella {dest_absolute}")

        # Header scan
        print(f"\n{'='*60}")
        print(f"--- AVVIO SCANSIONE {'(DRY-RUN)' if dry_run else ''} ---")
        print(f"{'='*60}")
        print(f"📁 Root: {roots}")
        print(f"🔍 Estensioni: {estensioni_target}")
        if query_nome:
            print(f"🏷️  Filtro nome (Fuzzy): '{query_nome}'")
        if min_size or max_size:
            min_str = self.format_size(min_size) if min_size else "N/A"
            max_str = self.format_size(max_size) if max_size else "N/A"
            print(f"📏 Dimensione: {min_str} - {max_str}")
        if date_from or date_to:
            from_str = date_from.strftime("%Y-%m-%d") if date_from else "N/A"
            to_str = date_to.strftime("%Y-%m-%d") if date_to else "N/A"
            print(f"📅 Date: {from_str} - {to_str}")
        print(f"🔒 Deduplicazione: {'ON' if deduplicate else 'OFF'}")
        print(f"{'='*60}\n")
        
        # Prima passata: conta file totali per progress (opzionale, può rallentare)
        # Per ora usiamo progress incrementale senza totale
        
        for root_dir in roots:
            # ✅ FIX BUG: followlinks=False previene loop infiniti e duplicati da symlink
            for current_root, dirs, files in os.walk(root_dir, topdown=True, followlinks=False):
                
                # --- FILTRO SICUREZZA ---
                # 1. Filtra cartelle di sistema pericolose
                # 2. Filtra cartelle nascoste (iniziano con .)
                # 3. ✅ ANTI-OUROBOROS: Filtra la cartella di destinazione!
                current_path = Path(current_root).resolve()
                
                # Rimuove dirs da scansionare se:
                # - Nome in SKIP_DIRS (sistema)
                # - Nome inizia con . (nascosta)
                # - Path completo coincide con destinazione (OUROBOROS!)
                original_dirs_count = len(dirs)
                dirs[:] = [
                    d for d in dirs 
                    if d not in SKIP_DIRS 
                    and not d.startswith('.')
                    and (current_path / d).resolve() != dest_absolute
                ]
                
                # Conta se abbiamo skippato la cartella destinazione
                if len(dirs) < original_dirs_count:
                    for d in set(os.listdir(current_root) if os.path.isdir(current_root) else []) - set(dirs):
                        if (current_path / d).resolve() == dest_absolute:
                            dest_folder_skipped += 1
                            if show_progress:
                                print(f"🚫 [ANTI-OUROBOROS] Saltata cartella destinazione: {dest_absolute}")
                            break
                
                for file in files:
                    # Gestione estensioni
                    ext = os.path.splitext(file)[1].lower()
                    
                    if ext in estensioni_target:
                        # Controllo nome (fuzzy)
                        if self.fuzzy_match(file, query_nome):
                            source_path = Path(current_root) / file
                            
                            try:
                                # Ottieni metadati file
                                file_stat = source_path.stat()
                                file_size = file_stat.st_size
                                file_mtime = file_stat.st_mtime
                                
                                # [FEATURE 4] Filtri dimensione e data
                                if not self.check_size_filter(file_size, min_size, max_size):
                                    files_filtrati += 1
                                    self.scan_log.append({
                                        "file": str(source_path),
                                        "status": "filtered_size",
                                        "size": file_size
                                    })
                                    continue
                                
                                if not self.check_date_filter(file_mtime, date_from, date_to):
                                    files_filtrati += 1
                                    self.scan_log.append({
                                        "file": str(source_path),
                                        "status": "filtered_date",
                                        "mtime": datetime.fromtimestamp(file_mtime).isoformat()
                                    })
                                    continue
                                
                                # [FEATURE 2] Hash deduplication
                                if deduplicate:
                                    file_hash = self.calculate_file_hash(source_path)
                                    if file_hash in self.processed_hashes:
                                        files_duplicati += 1
                                        self.scan_log.append({
                                            "file": str(source_path),
                                            "status": "duplicate",
                                            "hash": file_hash
                                        })
                                        continue
                                    self.processed_hashes.add(file_hash)
                                
                                # Struttura destinazione
                                dest_subfolder = path_dest / ext.replace('.', '').upper()
                                if not dry_run:
                                    dest_subfolder.mkdir(exist_ok=True)
                                
                                dest_path = dest_subfolder / file
                                
                                # Gestione Duplicati Nome (Rinomina se esiste)
                                counter = 1
                                while dest_path.exists() and not dry_run:
                                    dest_path = dest_subfolder / f"{source_path.stem}_{counter}{source_path.suffix}"
                                    counter += 1
                                
                                # [FEATURE 3] Progress
                                if show_progress:
                                    print(f"[{'DRY-RUN' if dry_run else mode.upper()}] {file} ({self.format_size(file_size)})")
                                
                                # [FEATURE 5] Dry-run: non esegue operazioni
                                if not dry_run:
                                    if mode == "move":
                                        shutil.move(str(source_path), str(dest_path))
                                    else:
                                        shutil.copy2(str(source_path), str(dest_path))
                                
                                files_trovati += 1
                                total_size += file_size

                                if progress_callback:
                                    try:
                                        # Invia alla GUI il messaggio e il conteggio attuale
                                        progress_callback(f"Elaborato: {file}", files_trovati)
                                    except Exception:
                                        pass # Se la GUI viene chiusa, non crashare
                                
                                # Log dettagliato
                                self.scan_log.append({
                                    "file": str(source_path),
                                    "destination": str(dest_path) if not dry_run else "N/A (dry-run)",
                                    "status": "success",
                                    "size": file_size,
                                    "size_formatted": self.format_size(file_size),
                                    "modified": datetime.fromtimestamp(file_mtime).isoformat(),
                                    "hash": file_hash if deduplicate else None,
                                    "mode": mode
                                })
                                
                            except Exception as e:
                                files_errori += 1
                                self.scan_log.append({
                                    "file": str(source_path),
                                    "status": "error",
                                    "error": str(e)
                                })

        # --- REPORT FINALE ---
        report = {
            "status": "success",
            "mode": "DRY-RUN" if dry_run else mode.upper(),
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "files_trovati": files_trovati,
                "files_duplicati": files_duplicati,
                "files_filtrati": files_filtrati,
                "files_errori": files_errori,
                "dest_folder_skipped": dest_folder_skipped,  # ✅ Anti-Ouroboros stat
                "total_size": total_size,
                "total_size_formatted": self.format_size(total_size)
            },
            "filters": {
                "extensions": estensioni_target,
                "name_query": query_nome,
                "min_size": min_size,
                "max_size": max_size,
                "date_from": date_from.isoformat() if date_from else None,
                "date_to": date_to.isoformat() if date_to else None,
                "deduplicate": deduplicate
            },
            "destination": str(path_dest),
            "log": self.scan_log if generate_report else []
        }
        
        # [FEATURE 5] Salva report JSON se richiesto
        if generate_report:
            report_path = path_dest / f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            try:
                with open(report_path, 'w', encoding='utf-8') as f:
                    json.dump(report, f, indent=2, ensure_ascii=False)
                print(f"\n📄 Report salvato in: {report_path}")
            except Exception as e:
                print(f"\n⚠️  Impossibile salvare report: {e}")
        
        # Messaggio finale
        message = f"""
{'='*60}
🎯 SCANSIONE COMPLETATA {'(MODALITÀ ANTEPRIMA)' if dry_run else ''}
{'='*60}
✅ File processati: {files_trovati}
🔄 Duplicati saltati: {files_duplicati}
🚫 Filtrati (size/date): {files_filtrati}
🛡️  Cartella destinazione skippata: {dest_folder_skipped}x (Anti-Ouroboros)
❌ Errori/Permessi negati: {files_errori}
💾 Dimensione totale: {self.format_size(total_size)}
{'='*60}
"""
        
        report["message"] = message
        print(message)
        
        return report


# --- INTERFACCIA TESTUALE MIGLIORATA ---
if __name__ == "__main__":
    hunter = FileHunter()
    
    print("\n" + "="*60)
    print("🚀 FILEHUNTER - TOOL DI RECUPERO FILE AVANZATO")
    print("="*60)
    
    # 1. Estensioni
    ext_input = input("\n📎 Inserisci estensioni separate da virgola (es. .jpg,.pdf,.docx): ")
    estensioni = [e.strip() for e in ext_input.split(',')]
    
    # 2. Destinazione
    dest = input("📁 Dove salvo i file trovati? (Percorso cartella): ")
    
    # 3. Nome (Fuzzing)
    nome = input("🏷️  Cerchi un nome file specifico? (Invio per saltare): ").strip() or None
    
    # 4. Modalità
    scelta = input("⚙️  Vuoi COPIARE (c) o SPOSTARE (m)? [c/m]: ").lower()
    modalita = "move" if scelta == 'm' else "copy"
    
    # 5. NUOVE OPZIONI AVANZATE
    print("\n--- OPZIONI AVANZATE (Invio per saltare) ---")
    
    # Deduplicazione
    dedup = input("🔒 Abilitare deduplicazione hash? [S/n]: ").lower()
    deduplicate = dedup != 'n'
    
    # Dimensione
    min_size_input = input("📏 Dimensione minima file (es. 1MB, 500KB, Invio per nessun limite): ").strip()
    min_size = None
    if min_size_input:
        try:
            # Parse semplice: 1MB = 1*1024*1024
            if 'mb' in min_size_input.lower():
                min_size = int(float(min_size_input.lower().replace('mb', '').strip()) * 1024 * 1024)
            elif 'kb' in min_size_input.lower():
                min_size = int(float(min_size_input.lower().replace('kb', '').strip()) * 1024)
            else:
                min_size = int(min_size_input)
        except:
            print("⚠️  Formato non valido, ignoro filtro dimensione minima")
    
    max_size_input = input("📏 Dimensione massima file (es. 100MB, Invio per nessun limite): ").strip()
    max_size = None
    if max_size_input:
        try:
            if 'mb' in max_size_input.lower():
                max_size = int(float(max_size_input.lower().replace('mb', '').strip()) * 1024 * 1024)
            elif 'kb' in max_size_input.lower():
                max_size = int(float(max_size_input.lower().replace('kb', '').strip()) * 1024)
            else:
                max_size = int(max_size_input)
        except:
            print("⚠️  Formato non valido, ignoro filtro dimensione massima")
    
    # Dry-run
    dry = input("🔍 Modalità anteprima (non copia/sposta file)? [s/N]: ").lower()
    dry_run = dry == 's'
    
    # Report
    report = input("📄 Generare report JSON dettagliato? [s/N]: ").lower()
    generate_report = report == 's'
    
    print("\n🔎 Inizio ricerca... Potrebbe volerci un po' se scansioni tutto il disco.")
    
    result = hunter.scan_and_process(
        estensioni_target=estensioni,
        cartella_destinazione=dest,
        query_nome=nome,
        mode=modalita,
        deduplicate=deduplicate,
        min_size=min_size,
        max_size=max_size,
        dry_run=dry_run,
        generate_report=generate_report,
        show_progress=True
    )