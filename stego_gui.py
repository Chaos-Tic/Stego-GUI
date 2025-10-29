#!/usr/bin/env python3
"""
Interface graphique simple pour dissimuler un fichier dans un autre
et pour extraire un fichier dissimulé.

Principe: on concatène au fichier porteur une signature, quelques
métadonnées (taille, nom d'origine) et enfin les octets du fichier caché.
Cette approche fonctionne avec la plupart des formats binaires, mais il
faut connaître ce procédé pour récupérer le contenu caché.
"""

import json
import os
import struct
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

MARKER = b"STEG_GUI_V1"
META_LEN_SIZE = 4  # Taille (en octets) du champ longueur des métadonnées
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "Evil_Files"  # Dossier cible imposé pour les fichiers fusionnés


def _locate_embedded_chunks(data: bytes) -> tuple[dict, bytes]:
    """Retourne les métadonnées décodées et les octets du payload."""
    search_end = len(data)
    while True:
        marker_index = data.rfind(MARKER, 0, search_end)
        if marker_index == -1:
            raise ValueError("Aucune signature de données cachées détectée.")
        meta_start = marker_index + len(MARKER)
        if len(data) < meta_start + META_LEN_SIZE:
            search_end = marker_index
            continue
        meta_len = struct.unpack(">I", data[meta_start : meta_start + META_LEN_SIZE])[0]
        meta_bytes_start = meta_start + META_LEN_SIZE
        meta_bytes_end = meta_bytes_start + meta_len
        if meta_len <= 0 or meta_bytes_end > len(data):
            search_end = marker_index
            continue
        meta_chunk = data[meta_bytes_start:meta_bytes_end]
        try:
            metadata = json.loads(meta_chunk.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            search_end = marker_index
            continue
        payload_bytes = data[meta_bytes_end:]
        return metadata, payload_bytes


def embed_file(carrier_path: str, payload_paths: list[str], output_name: str) -> Path:
    """Fusionne le fichier porteur et un ou plusieurs fichiers à cacher dans Evil_Files."""
    carrier = Path(carrier_path).expanduser()
    if not payload_paths:
        raise ValueError("Aucun fichier à dissimuler n'a été fourni.")
    payload_files = [Path(path).expanduser() for path in payload_paths]
    raw_name = (output_name or "").strip()
    if not raw_name:
        raise ValueError("Nom de fichier de sortie manquant.")
    safe_name = os.path.basename(raw_name)
    if not safe_name or safe_name in {".", ".."}:
        raise ValueError("Nom de fichier de sortie invalide.")
    if any(sep and sep in safe_name for sep in (os.sep, os.altsep)):
        raise ValueError("Le nom de fichier ne doit pas contenir de séparateur de chemin.")
    output = OUTPUT_DIR / safe_name

    if not carrier.is_file():
        raise FileNotFoundError(f"Fichier porteur introuvable: {carrier}")
    missing = [str(path) for path in payload_files if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Fichiers à cacher introuvables: {', '.join(missing)}")

    if carrier.resolve() == output.resolve():
        raise ValueError("Le fichier de sortie doit être différent du fichier porteur.")
    for payload in payload_files:
        if payload.resolve() == output.resolve():
            raise ValueError("Le fichier de sortie doit être différent des fichiers à cacher.")

    output_parent = output.parent
    if output_parent and not output_parent.exists():
        output_parent.mkdir(parents=True, exist_ok=True)

    payload_chunks: list[bytes] = []
    files_meta: list[dict[str, object]] = []
    for payload in payload_files:
        chunk = payload.read_bytes()
        payload_chunks.append(chunk)
        files_meta.append(
            {
                "filename": payload.name,
                "size": len(chunk),
            }
        )
    metadata = {
        "files": files_meta,
        "count": len(files_meta),
    }
    metadata_bytes = json.dumps(metadata).encode("utf-8")
    if len(metadata_bytes) > 2**32 - 1:
        raise ValueError("Métadonnées trop volumineuses.")

    with carrier.open("rb") as carrier_file, output.open("wb") as out_file:
        out_file.write(carrier_file.read())
        out_file.write(MARKER)
        out_file.write(struct.pack(">I", len(metadata_bytes)))
        out_file.write(metadata_bytes)
        for chunk in payload_chunks:
            out_file.write(chunk)
    return output


def extract_file(stego_path: str, output_dir: str) -> list[Path]:
    """Extrait les fichiers cachés depuis stego_path vers output_dir."""
    stego_file = Path(stego_path)
    target_dir = Path(output_dir)

    if not stego_file.is_file():
        raise FileNotFoundError(f"Fichier dissimulé introuvable: {stego_file}")

    if not target_dir.exists():
        target_dir.mkdir(parents=True, exist_ok=True)
    elif not target_dir.is_dir():
        raise NotADirectoryError(f"Chemin de sortie invalide: {target_dir}")

    data = stego_file.read_bytes()
    metadata, payload_bytes = _locate_embedded_chunks(data)

    files_meta = metadata.get("files")
    if not isinstance(files_meta, list) or not files_meta:
        legacy_name = metadata.get("filename")
        legacy_size = metadata.get("size")
        if isinstance(legacy_name, str) and isinstance(legacy_size, int):
            files_meta = [{"filename": legacy_name, "size": legacy_size}]
        else:
            raise ValueError("Métadonnées de fichiers absentes ou invalides.")

    extracted_paths: list[Path] = []
    offset = 0
    for index, file_meta in enumerate(files_meta, start=1):
        filename = file_meta.get("filename")
        size = file_meta.get("size")
        if not isinstance(filename, str) or not isinstance(size, int):
            raise ValueError("Métadonnées de fichier corrompues.")
        if size < 0:
            raise ValueError("Taille de fichier négative dans les métadonnées.")
        chunk = payload_bytes[offset : offset + size]
        if len(chunk) != size:
            raise ValueError("Taille du fichier caché incohérente: extraction abandonnée.")
        offset += size

        base_name = os.path.basename(filename) or f"fichier_cache_{index}"
        output_file = target_dir / base_name
        if output_file.exists():
            overwrite = messagebox.askyesno(
                "Confirmer le remplacement",
                f"Le fichier {output_file} existe déjà. Voulez-vous le remplacer ?",
            )
            if not overwrite:
                raise FileExistsError(f"Fichier déjà présent: {output_file}")
        output_file.write_bytes(chunk)
        extracted_paths.append(output_file)

    if offset != len(payload_bytes):
        raise ValueError("Octets supplémentaires inattendus après les fichiers extraits.")

    return extracted_paths


class StegoGUI:
    """Fenêtre principale de l'application."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Dissimuler un fichier")
        self.root.geometry("720x520")
        self.root.resizable(True, True)
        self._setup_styles()
        self.root.configure(bg="#0f172a")
        self._valid_flags = {
            "carrier": False,
            "payload": False,
            "output": False,
            "stego": False,
            "output_dir": False,
        }

        container = ttk.Frame(root, style="Main.TFrame", padding=(20, 16, 20, 18))
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container, style="Main.TFrame")
        header.pack(fill=tk.X, pady=(0, 12))
        title = ttk.Label(header, text="StegoGUI", style="Title.TLabel")
        title.pack(anchor="w")
        subtitle = ttk.Label(
            header,
            text="Cachez et extrayez facilement des fichiers à l'intérieur d'autres fichiers.",
            style="Subtitle.TLabel",
        )
        subtitle.pack(anchor="w", pady=(4, 0))

        notebook = ttk.Notebook(container, style="Card.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)

        self.embed_tab = ttk.Frame(notebook, padding=20, style="Card.TFrame")
        self.extract_tab = ttk.Frame(notebook, padding=20, style="Card.TFrame")
        notebook.add(self.embed_tab, text="Cacher un fichier")
        notebook.add(self.extract_tab, text="Extraire un fichier")

        self.payload_paths: list[str] = []
        self.payload_summary_var = tk.StringVar(value="Aucun fichier sélectionné")

        self._build_embed_tab()
        self._build_extract_tab()
        self.carrier_var.trace_add("write", lambda *_: self._refresh_embed_state())
        self.output_var.trace_add("write", lambda *_: self._refresh_embed_state())
        self.stego_var.trace_add("write", lambda *_: self._refresh_extract_state())
        self.output_dir_var.trace_add("write", lambda *_: self._refresh_extract_state())
        self._update_payload_summary()
        self._refresh_embed_state()
        self._refresh_extract_state()

    def _setup_styles(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        primary_bg = "#0f172a"
        card_bg = "#1f2937"
        accent = "#2563eb"
        text_primary = "#f8fafc"
        text_secondary = "#cbd5f5"

        style.configure("Main.TFrame", background=primary_bg)
        style.configure("Title.TLabel", background=primary_bg, foreground=text_primary, font=("Segoe UI", 18, "bold"))
        style.configure("Subtitle.TLabel", background=primary_bg, foreground=text_secondary, font=("Segoe UI", 10))
        style.configure("Card.TFrame", background=card_bg)
        style.configure("CardInner.TFrame", background=card_bg)
        style.configure("TLabel", background=card_bg, foreground=text_secondary, font=("Segoe UI", 10))
        style.configure("FieldLabel.TLabel", background=card_bg, foreground=text_primary, font=("Segoe UI", 11, "bold"))
        style.configure("Status.TLabel", background=card_bg, foreground="#22c55e", font=("Segoe UI", 10, "italic"))
        style.configure("Warning.TLabel", background=card_bg, foreground="#f97316", font=("Segoe UI", 10, "italic"))
        style.configure(
            "Card.TNotebook",
            background=primary_bg,
            borderwidth=0,
            padding=0,
        )
        style.configure("TNotebook", background=primary_bg, borderwidth=0, relief="flat")
        style.configure(
            "TNotebook.Tab",
            background=primary_bg,
            foreground=text_secondary,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", card_bg)],
            foreground=[("selected", text_primary)],
        )
        style.configure(
            "Primary.TButton",
            background=accent,
            foreground=text_primary,
            padding=(16, 8),
            font=("Segoe UI", 11, "bold"),
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", "#1d4ed8")],
            foreground=[("disabled", "#9ca3af")],
        )
        style.configure(
            "Toolbar.TButton",
            background="#334155",
            foreground=text_primary,
            padding=(12, 6),
            font=("Segoe UI", 10),
        )
        style.map(
            "Toolbar.TButton",
            background=[("active", "#475569")],
            foreground=[("disabled", "#64748b")],
        )
        style.configure(
            "Modern.TEntry",
            fieldbackground="#111827",
            foreground=text_primary,
            insertcolor=text_primary,
            padding=(10, 8),
            borderwidth=0,
            relief="flat",
        )
        style.map(
            "Modern.TEntry",
            fieldbackground=[("disabled", "#1e293b")],
            foreground=[("disabled", "#64748b")],
        )

    def _build_embed_tab(self) -> None:
        fields = ttk.Frame(self.embed_tab, style="CardInner.TFrame")
        fields.grid(row=0, column=0, sticky="nsew")
        self.embed_tab.columnconfigure(0, weight=1)

        carrier_label = ttk.Label(fields, text="Fichier porteur", style="FieldLabel.TLabel")
        carrier_label.grid(row=0, column=0, sticky="w")
        carrier_hint = ttk.Label(fields, text="(chemin libre vers le fichier porteur)", style="TLabel")
        carrier_hint.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.carrier_var = tk.StringVar()
        carrier_entry = ttk.Entry(fields, textvariable=self.carrier_var, width=48, style="Modern.TEntry")
        carrier_entry.grid(row=2, column=0, sticky="we", pady=(4, 10))
        self.carrier_indicator = self._create_indicator(fields)
        self.carrier_indicator.grid(row=2, column=2, padx=(8, 0))
        carrier_button = ttk.Button(
            fields, text="Parcourir", command=self._select_carrier, style="Toolbar.TButton"
        )
        carrier_button.grid(row=2, column=1, padx=(8, 0), sticky="e")

        payload_label = ttk.Label(fields, text="Fichiers à dissimuler", style="FieldLabel.TLabel")
        payload_label.grid(row=3, column=0, sticky="w")
        payload_hint = ttk.Label(
            fields,
            text="(sélection libre, un ou plusieurs fichiers)",
            style="TLabel",
        )
        payload_hint.grid(row=4, column=0, sticky="w", pady=(2, 0))
        payload_summary = ttk.Label(
            fields,
            textvariable=self.payload_summary_var,
            style="TLabel",
            anchor="w",
            justify="left",
            wraplength=360,
        )
        payload_summary.grid(row=5, column=0, sticky="we", pady=(4, 10))
        self.payload_indicator = self._create_indicator(fields)
        self.payload_indicator.grid(row=5, column=2, padx=(8, 0))
        payload_buttons = ttk.Frame(fields, style="CardInner.TFrame")
        payload_buttons.grid(row=6, column=0, columnspan=2, sticky="w")
        payload_button = ttk.Button(
            payload_buttons,
            text="Choisir des fichiers...",
            command=self._select_payloads,
            style="Toolbar.TButton",
        )
        payload_button.grid(row=0, column=0, padx=(0, 8), sticky="w")
        clear_button = ttk.Button(
            payload_buttons,
            text="Vider la sélection",
            command=self._clear_payloads,
            style="Toolbar.TButton",
        )
        clear_button.grid(row=0, column=1, sticky="w")

        output_label = ttk.Label(
            fields,
            text="Nom du fichier combiné (stocké dans Evil_Files)",
            style="FieldLabel.TLabel",
        )
        output_label.grid(row=7, column=0, sticky="w")
        output_hint = ttk.Label(
            fields,
            text="(nom uniquement, sans chemin : sera créé dans Evil_Files)",
            style="TLabel",
        )
        output_hint.grid(row=8, column=0, sticky="w", pady=(2, 0))
        self.output_var = tk.StringVar()
        output_entry = ttk.Entry(fields, textvariable=self.output_var, width=48, style="Modern.TEntry")
        output_entry.grid(row=9, column=0, sticky="we", pady=(4, 10))
        self.output_indicator = self._create_indicator(fields)
        self.output_indicator.grid(row=9, column=2, padx=(8, 0))
        output_button = ttk.Button(
            fields, text="Renommer...", command=self._select_output, style="Toolbar.TButton"
        )
        output_button.grid(row=9, column=1, padx=(8, 0), sticky="e")

        self.embed_button = ttk.Button(
            fields, text="Procéder", command=self._handle_embed, style="Primary.TButton", state=tk.DISABLED
        )
        self.embed_button.grid(row=10, column=0, columnspan=2, pady=(16, 0), sticky="ew")

        self.embed_status = ttk.Label(fields, text="", style="Status.TLabel")
        self.embed_status.grid(row=11, column=0, columnspan=2, pady=(12, 0), sticky="w")

        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(2, weight=0)

    def _build_extract_tab(self) -> None:
        fields = ttk.Frame(self.extract_tab, style="CardInner.TFrame")
        fields.grid(row=0, column=0, sticky="nsew")
        self.extract_tab.columnconfigure(0, weight=1)

        stego_label = ttk.Label(fields, text="Fichier combiné", style="FieldLabel.TLabel")
        stego_label.grid(row=0, column=0, sticky="w")
        stego_hint = ttk.Label(
            fields,
            text="(choisir un fichier présent dans Evil_Files)",
            style="TLabel",
        )
        stego_hint.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self.stego_var = tk.StringVar()
        stego_entry = ttk.Entry(fields, textvariable=self.stego_var, width=48, style="Modern.TEntry")
        stego_entry.grid(row=2, column=0, sticky="we", pady=(4, 10))
        self.stego_indicator = self._create_indicator(fields)
        self.stego_indicator.grid(row=2, column=2, padx=(8, 0))
        stego_button = ttk.Button(
            fields, text="Parcourir", command=self._select_stego, style="Toolbar.TButton"
        )
        stego_button.grid(row=2, column=1, padx=(8, 0), sticky="e")

        output_dir_label = ttk.Label(fields, text="Dossier de sortie", style="FieldLabel.TLabel")
        output_dir_label.grid(row=3, column=0, sticky="w")
        output_dir_hint = ttk.Label(
            fields,
            text="(chemin du dossier cible : sera créé si nécessaire)",
            style="TLabel",
        )
        output_dir_hint.grid(row=4, column=0, sticky="w", pady=(2, 0))
        self.output_dir_var = tk.StringVar()
        output_dir_entry = ttk.Entry(fields, textvariable=self.output_dir_var, width=48, style="Modern.TEntry")
        output_dir_entry.grid(row=5, column=0, sticky="we", pady=(4, 10))
        self.output_dir_indicator = self._create_indicator(fields)
        self.output_dir_indicator.grid(row=5, column=2, padx=(8, 0))
        output_dir_button = ttk.Button(
            fields, text="Choisir", command=self._select_output_dir, style="Toolbar.TButton"
        )
        output_dir_button.grid(row=5, column=1, padx=(8, 0), sticky="e")

        extract_button = ttk.Button(
            fields, text="Extraire le fichier", command=self._handle_extract, style="Primary.TButton"
        )
        extract_button.grid(row=6, column=0, columnspan=2, pady=(16, 0), sticky="ew")

        self.extract_status = ttk.Label(fields, text="", style="Status.TLabel")
        self.extract_status.grid(row=7, column=0, columnspan=2, pady=(12, 0), sticky="w")

        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(2, weight=0)

    def _select_carrier(self) -> None:
        path = filedialog.askopenfilename(title="Choisir le fichier porteur")
        if path:
            self.carrier_var.set(path)
            current_output = self.output_var.get().strip()
            if not current_output:
                suggested = self._suggest_output_path(path)
                self.output_var.set(suggested)

    def _select_payloads(self) -> None:
        paths = filedialog.askopenfilenames(title="Choisir les fichiers à cacher")
        if paths:
            self.payload_paths = [str(Path(path).expanduser()) for path in paths]
            self._update_payload_summary()
            self._refresh_embed_state()

    def _clear_payloads(self) -> None:
        self.payload_paths = []
        self._update_payload_summary()
        self._refresh_embed_state()

    def _update_payload_summary(self) -> None:
        if not self.payload_paths:
            summary = "Aucun fichier sélectionné"
        else:
            names = [Path(path).name for path in self.payload_paths]
            count = len(names)
            if count <= 3:
                lines = "\n".join(f"- {name}" for name in names)
                summary = f"{count} fichier(s) sélectionné(s) :\n{lines}"
            else:
                displayed = ", ".join(names[:3])
                summary = f"{count} fichiers sélectionnés : {displayed}, ..."
        self.payload_summary_var.set(summary)

    def _select_output(self) -> None:
        carrier_path = self.carrier_var.get().strip()
        initial_name = ""
        if carrier_path:
            initial_name = self._suggest_output_path(carrier_path)
        name = simpledialog.askstring(
            "Nommer le fichier combiné",
            "Indiquez le nom du fichier combiné (sans chemin).\n"
            f"Il sera enregistré dans :\n{OUTPUT_DIR}",
            initialvalue=initial_name or "fichier_combine",
        )
        if name:
            self.output_var.set(name.strip())

    def _select_stego(self) -> None:
        path = filedialog.askopenfilename(
            title="Choisir le fichier combiné",
            initialdir=OUTPUT_DIR,
        )
        if path:
            selected = Path(path).expanduser()
            try:
                selected.relative_to(OUTPUT_DIR)
            except ValueError:
                messagebox.showwarning(
                    "Emplacement invalide",
                    f"Veuillez choisir un fichier situé dans :\n{OUTPUT_DIR}",
                )
                return
            self.stego_var.set(str(selected))

    def _select_output_dir(self) -> None:
        path = filedialog.askdirectory(title="Choisir le dossier de sortie")
        if path:
            self.output_dir_var.set(path)

    def _handle_embed(self) -> None:
        carrier = self.carrier_var.get().strip()
        payloads = list(self.payload_paths)
        output = self.output_var.get().strip()

        if not self._valid_flags["carrier"] or not self._valid_flags["payload"] or not self._valid_flags["output"]:
            messagebox.showwarning(
                "Champs incomplets", "Merci de renseigner des chemins valides avant de procéder."
            )
            return

        self._set_status(self.embed_status, "", success=True)

        try:
            output_path = embed_file(carrier, payloads, output)
        except Exception as exc:  # noqa: BLE001 - on affiche le message à l'utilisateur.
            self._report_error(
                "Erreur d'incrustation",
                f"Impossible de cacher le fichier.\nDétail: {exc}",
                self.embed_status,
                exc,
            )
        else:
            if not output_path.exists():
                self._report_error(
                    "Fichier introuvable",
                    "Le fichier combiné n'a pas été localisé après l'opération.",
                    self.embed_status,
                    FileNotFoundError(str(output_path)),
                )
                return
            self._set_status(
                self.embed_status,
                f"{len(payloads)} fichier(s) caché(s) avec succès dans : {output_path}",
                success=True,
            )
            messagebox.showinfo(
                "Succès",
                f"{len(payloads)} fichier(s) ont été combinés dans :\n{output_path}",
            )

    def _handle_extract(self) -> None:
        stego_path = self.stego_var.get().strip()
        output_dir = self.output_dir_var.get().strip()

        if not stego_path or not output_dir:
            messagebox.showwarning(
                "Champs incomplets", "Veuillez choisir un fichier combiné et un dossier de sortie."
            )
            return

        self._set_status(self.extract_status, "", success=True)

        try:
            extracted_paths = extract_file(stego_path, output_dir)
        except Exception as exc:  # noqa: BLE001 - le message est remonté à l'écran.
            self._report_error(
                "Erreur d'extraction",
                f"Impossible d'extraire le fichier.\nDétail: {exc}",
                self.extract_status,
                exc,
            )
        else:
            names = ", ".join(path.name for path in extracted_paths)
            self._set_status(
                self.extract_status,
                f"{len(extracted_paths)} fichier(s) extrait(s) : {names}",
                success=True,
            )

    @staticmethod
    def _suggest_output_path(carrier_path: str) -> str:
        carrier = Path(carrier_path)
        stem = carrier.stem or carrier.name
        suffix = carrier.suffix
        suggestion = f"{stem}_stego{suffix}"
        return suggestion

    def _refresh_embed_state(self) -> None:
        carrier = self.carrier_var.get().strip()
        payloads = list(self.payload_paths)
        output = self.output_var.get().strip()

        carrier_path = Path(carrier).expanduser() if carrier else None
        payload_paths = [Path(path).expanduser() for path in payloads]

        carrier_valid = bool(carrier_path and carrier_path.is_file())
        payload_valid = bool(
            len(payload_paths) >= 1 and all(path.is_file() for path in payload_paths)
        )
        output_valid = False
        if output:
            has_separator = any(sep and sep in output for sep in (os.sep, os.altsep))
            output_valid = not has_separator and output not in {"", ".", ".."}

        self._valid_flags["carrier"] = carrier_valid
        self._valid_flags["payload"] = payload_valid
        self._valid_flags["output"] = bool(output) and output_valid

        self._update_indicator(self.carrier_indicator, carrier_valid)
        self._update_indicator(self.payload_indicator, payload_valid)
        self._update_indicator(self.output_indicator, self._valid_flags["output"])

        if all(self._valid_flags[key] for key in ("carrier", "payload", "output")):
            self.embed_button.configure(state=tk.NORMAL)
        else:
            self.embed_button.configure(state=tk.DISABLED)

    def _refresh_extract_state(self) -> None:
        stego = self.stego_var.get().strip()
        output_dir = self.output_dir_var.get().strip()

        stego_path = Path(stego).expanduser() if stego else None
        output_dir_path = Path(output_dir).expanduser() if output_dir else None

        stego_valid = bool(
            stego_path
            and stego_path.is_file()
            and stego_path.resolve().is_relative_to(OUTPUT_DIR)
        )
        output_dir_valid = False
        if output_dir_path:
            if output_dir_path.exists():
                output_dir_valid = output_dir_path.is_dir()
            else:
                output_dir_valid = bool(output_dir_path.parent and output_dir_path.parent.exists())

        self._valid_flags["stego"] = stego_valid
        self._valid_flags["output_dir"] = bool(output_dir) and output_dir_valid

        self._update_indicator(self.stego_indicator, stego_valid)
        self._update_indicator(self.output_dir_indicator, self._valid_flags["output_dir"])

    def _set_status(self, label: ttk.Label, message: str, *, success: bool) -> None:
        color = "#1a7f37" if success else "#b91d1d"
        label.configure(text=message, foreground=color)

    def _report_error(
        self,
        title: str,
        message: str,
        label: ttk.Label,
        exc: Exception,
    ) -> None:
        label_message = message or str(exc)
        self._set_status(label, label_message, success=False)
        messagebox.showerror(title, message)
        traceback.print_exception(exc)

    @staticmethod
    def _create_indicator(parent: ttk.Frame) -> ttk.Label:
        indicator = ttk.Label(parent, text="X", style="Warning.TLabel")
        indicator.configure(foreground="#ef4444")
        return indicator

    def _update_indicator(self, indicator: ttk.Label, is_valid: bool) -> None:
        indicator.configure(
            text="V" if is_valid else "X",
            foreground="#22c55e" if is_valid else "#ef4444",
        )


def main() -> None:
    root = tk.Tk()
    StegoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
