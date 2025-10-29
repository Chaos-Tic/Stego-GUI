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
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

MARKER = b"STEG_GUI_V1"
META_LEN_SIZE = 4  # Taille (en octets) du champ longueur des métadonnées
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "Evil_Files"  # Dossier cible imposé pour les fichiers fusionnés

LANGUAGES = ("fr", "en")
FLAG_EMOJIS = {"fr": "🇫🇷", "en": "🇬🇧"}
TRANSLATIONS = {
    "fr": {
        "app_title": "StegoGUI",
        "window_title": "Dissimuler un fichier",
        "subtitle": "Cachez et extrayez facilement des fichiers à l'intérieur d'autres fichiers.",
        "tab_embed": "Cacher un fichier",
        "tab_extract": "Extraire un fichier",
        "carrier_label": "Fichier porteur",
        "carrier_hint": "(chemin libre vers le fichier porteur)",
        "browse": "Parcourir",
        "payload_label": "Fichiers à dissimuler",
        "payload_hint": "(sélection libre, un ou plusieurs fichiers)",
        "payload_select": "Choisir des fichiers...",
        "payload_clear": "Vider la sélection",
        "payload_summary_none": "Aucun fichier sélectionné",
        "payload_summary_lines": "{count} fichier(s) sélectionné(s) :\n{lines}",
        "payload_summary_many": "{count} fichiers sélectionnés : {displayed}, ...",
        "output_label": "Nom du fichier combiné (stocké dans Evil_Files)",
        "output_hint": "(nom uniquement, sans chemin : sera créé dans Evil_Files)",
        "output_rename": "Renommer...",
        "embed_action": "Procéder",
        "stego_label": "Fichier combiné",
        "stego_hint": "(choisir un fichier présent dans Evil_Files)",
        "output_dir_label": "Dossier de sortie",
        "output_dir_hint": "(chemin du dossier cible : sera créé si nécessaire)",
        "output_dir_browse": "Choisir",
        "extract_action": "Extraire le fichier",
        "dialog_carrier_title": "Choisir le fichier porteur",
        "dialog_payload_title": "Choisir les fichiers à cacher",
        "dialog_output_prompt_title": "Nommer le fichier combiné",
        "dialog_output_prompt": "Indiquez le nom du fichier combiné (sans chemin).\nIl sera enregistré dans :\n{output_dir}",
        "default_output_name": "fichier_combine",
        "dialog_stego_title": "Choisir le fichier combiné",
        "dialog_invalid_location_title": "Emplacement invalide",
        "dialog_invalid_location_message": "Veuillez choisir un fichier situé dans :\n{output_dir}",
        "dialog_output_dir_title": "Choisir le dossier de sortie",
        "fields_incomplete_title": "Champs incomplets",
        "fields_incomplete_embed_message": "Merci de renseigner des chemins valides avant de procéder.",
        "fields_incomplete_extract_message": "Veuillez choisir un fichier combiné et un dossier de sortie.",
        "error_embed_title": "Erreur d'incrustation",
        "error_embed_message": "Impossible de cacher le fichier.\nDétail: {error}",
        "error_missing_output_title": "Fichier introuvable",
        "error_missing_output_message": "Le fichier combiné n'a pas été localisé après l'opération.",
        "success_title": "Succès",
        "embed_success_status": "{count} fichier(s) caché(s) avec succès dans : {path}",
        "embed_success_message": "{count} fichier(s) ont été combinés dans :\n{path}",
        "error_extract_title": "Erreur d'extraction",
        "error_extract_message": "Impossible d'extraire le fichier.\nDétail: {error}",
        "extract_success_status": "{count} fichier(s) extrait(s) : {names}",
        "confirm_overwrite_title": "Confirmer le remplacement",
        "confirm_overwrite_message": "Le fichier {path} existe déjà. Voulez-vous le remplacer ?",
    },
    "en": {
        "app_title": "StegoGUI",
        "window_title": "Hide a file",
        "subtitle": "Hide and extract files inside other files with ease.",
        "tab_embed": "Hide file",
        "tab_extract": "Extract file",
        "carrier_label": "Carrier file",
        "carrier_hint": "(select any path to the carrier file)",
        "browse": "Browse",
        "payload_label": "Files to hide",
        "payload_hint": "(select one or more files)",
        "payload_select": "Select files...",
        "payload_clear": "Clear selection",
        "payload_summary_none": "No file selected",
        "payload_summary_lines": "{count} file(s) selected:\n{lines}",
        "payload_summary_many": "{count} files selected: {displayed}, ...",
        "output_label": "Combined file name (stored in Evil_Files)",
        "output_hint": "(name only, no path: saved in Evil_Files)",
        "output_rename": "Rename...",
        "embed_action": "Run",
        "stego_label": "Combined file",
        "stego_hint": "(choose a file located in Evil_Files)",
        "output_dir_label": "Output folder",
        "output_dir_hint": "(destination folder path: created if needed)",
        "output_dir_browse": "Select",
        "extract_action": "Extract file",
        "dialog_carrier_title": "Choose the carrier file",
        "dialog_payload_title": "Choose files to hide",
        "dialog_output_prompt_title": "Name the combined file",
        "dialog_output_prompt": "Enter the combined file name (no path).\nIt will be saved in:\n{output_dir}",
        "default_output_name": "combined_file",
        "dialog_stego_title": "Choose the combined file",
        "dialog_invalid_location_title": "Invalid location",
        "dialog_invalid_location_message": "Please select a file located in:\n{output_dir}",
        "dialog_output_dir_title": "Choose the output folder",
        "fields_incomplete_title": "Incomplete fields",
        "fields_incomplete_embed_message": "Please provide valid paths before proceeding.",
        "fields_incomplete_extract_message": "Please choose a combined file and an output folder.",
        "error_embed_title": "Embedding error",
        "error_embed_message": "Unable to hide the file.\nDetails: {error}",
        "error_missing_output_title": "File not found",
        "error_missing_output_message": "The combined file was not found after the operation.",
        "success_title": "Success",
        "embed_success_status": "{count} file(s) hidden successfully into: {path}",
        "embed_success_message": "{count} file(s) were combined into:\n{path}",
        "error_extract_title": "Extraction error",
        "error_extract_message": "Unable to extract the file.\nDetails: {error}",
        "extract_success_status": "{count} file(s) extracted: {names}",
        "confirm_overwrite_title": "Confirm replacement",
        "confirm_overwrite_message": "The file {path} already exists. Replace it?",
    },
}

CURRENT_LANGUAGE = "fr"


def translate(key: str, *, language: str | None = None, **kwargs) -> str:
    """Retourne la traduction associée à key pour la langue donnée."""
    lang = language or CURRENT_LANGUAGE
    bundle = TRANSLATIONS.get(lang) or TRANSLATIONS["fr"]
    fallback = TRANSLATIONS["en"]
    text = bundle.get(key) or fallback.get(key) or TRANSLATIONS["fr"].get(key, key)
    return text.format(**kwargs)


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
                translate("confirm_overwrite_title"),
                translate("confirm_overwrite_message", path=output_file),
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
        global CURRENT_LANGUAGE
        self.language = CURRENT_LANGUAGE
        CURRENT_LANGUAGE = self.language

        self._text_bindings: list[Callable[[], None]] = []
        self._language_buttons: dict[str, ttk.Button] = {}
        self.payload_paths: list[str] = []
        self._valid_flags = {
            "carrier": False,
            "payload": False,
            "output": False,
            "stego": False,
            "output_dir": False,
        }

        self.root.geometry("720x520")
        self.root.resizable(True, True)
        self._setup_styles()
        self.root.configure(bg="#0f172a")
        self.root.title(self._t("window_title"))
        self._bind_text(lambda: self.root.title(self._t("window_title")))

        container = ttk.Frame(root, style="Main.TFrame", padding=(20, 16, 20, 18))
        container.pack(fill=tk.BOTH, expand=True)

        header = ttk.Frame(container, style="Main.TFrame")
        header.pack(fill=tk.X, pady=(0, 12))
        top_row = ttk.Frame(header, style="Main.TFrame")
        top_row.pack(fill=tk.X)

        title = ttk.Label(top_row, text=self._t("app_title"), style="Title.TLabel")
        title.pack(side=tk.LEFT)
        self._bind_text(lambda w=title: w.configure(text=self._t("app_title")))

        lang_frame = ttk.Frame(top_row, style="Main.TFrame")
        lang_frame.pack(side=tk.RIGHT)
        for index, lang in enumerate(LANGUAGES):
            button = ttk.Button(
                lang_frame,
                text=FLAG_EMOJIS.get(lang, lang.upper()),
                command=lambda value=lang: self._switch_language(value),
                style="Lang.TButton",
                width=3,
                takefocus=0,
            )
            padding = (0, 0) if index == len(LANGUAGES) - 1 else (0, 6)
            button.pack(side=tk.LEFT, padx=padding)
            self._language_buttons[lang] = button

        subtitle = ttk.Label(header, text=self._t("subtitle"), style="Subtitle.TLabel")
        subtitle.pack(anchor="w", pady=(4, 0))
        self._bind_text(lambda w=subtitle: w.configure(text=self._t("subtitle")))

        notebook = ttk.Notebook(container, style="Card.TNotebook")
        notebook.pack(fill=tk.BOTH, expand=True)

        self.embed_tab = ttk.Frame(notebook, padding=20, style="Card.TFrame")
        self.extract_tab = ttk.Frame(notebook, padding=20, style="Card.TFrame")
        notebook.add(self.embed_tab, text=self._t("tab_embed"))
        notebook.add(self.extract_tab, text=self._t("tab_extract"))
        self._bind_text(lambda tab=self.embed_tab, nb=notebook: nb.tab(tab, text=self._t("tab_embed")))
        self._bind_text(lambda tab=self.extract_tab, nb=notebook: nb.tab(tab, text=self._t("tab_extract")))

        self.payload_summary_var = tk.StringVar(value=self._t("payload_summary_none"))

        self._build_embed_tab()
        self._build_extract_tab()
        self.carrier_var.trace_add("write", lambda *_: self._refresh_embed_state())
        self.output_var.trace_add("write", lambda *_: self._refresh_embed_state())
        self.stego_var.trace_add("write", lambda *_: self._refresh_extract_state())
        self.output_dir_var.trace_add("write", lambda *_: self._refresh_extract_state())
        self._update_payload_summary()
        self._refresh_embed_state()
        self._refresh_extract_state()
        self._update_language_buttons()

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
        style.configure(
            "Lang.TButton",
            background="#1e293b",
            foreground=text_primary,
            padding=(8, 4),
            font=("Segoe UI", 12),
            borderwidth=0,
        )
        style.map(
            "Lang.TButton",
            background=[("active", accent), ("disabled", accent)],
            foreground=[("disabled", text_primary)],
        )

    def _build_embed_tab(self) -> None:
        fields = ttk.Frame(self.embed_tab, style="CardInner.TFrame")
        fields.grid(row=0, column=0, sticky="nsew")
        self.embed_tab.columnconfigure(0, weight=1)

        carrier_label = ttk.Label(fields, text=self._t("carrier_label"), style="FieldLabel.TLabel")
        carrier_label.grid(row=0, column=0, sticky="w")
        self._bind_text(lambda w=carrier_label: w.configure(text=self._t("carrier_label")))
        carrier_hint = ttk.Label(fields, text=self._t("carrier_hint"), style="TLabel")
        carrier_hint.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self._bind_text(lambda w=carrier_hint: w.configure(text=self._t("carrier_hint")))
        self.carrier_var = tk.StringVar()
        carrier_entry = ttk.Entry(fields, textvariable=self.carrier_var, width=48, style="Modern.TEntry")
        carrier_entry.grid(row=2, column=0, sticky="we", pady=(4, 10))
        self.carrier_indicator = self._create_indicator(fields)
        self.carrier_indicator.grid(row=2, column=2, padx=(8, 0))
        carrier_button = ttk.Button(
            fields, text=self._t("browse"), command=self._select_carrier, style="Toolbar.TButton"
        )
        carrier_button.grid(row=2, column=1, padx=(8, 0), sticky="e")
        self._bind_text(lambda w=carrier_button: w.configure(text=self._t("browse")))

        payload_label = ttk.Label(fields, text=self._t("payload_label"), style="FieldLabel.TLabel")
        payload_label.grid(row=3, column=0, sticky="w")
        self._bind_text(lambda w=payload_label: w.configure(text=self._t("payload_label")))
        payload_hint = ttk.Label(
            fields,
            text=self._t("payload_hint"),
            style="TLabel",
        )
        payload_hint.grid(row=4, column=0, sticky="w", pady=(2, 0))
        self._bind_text(lambda w=payload_hint: w.configure(text=self._t("payload_hint")))
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
            text=self._t("payload_select"),
            command=self._select_payloads,
            style="Toolbar.TButton",
        )
        payload_button.grid(row=0, column=0, padx=(0, 8), sticky="w")
        self._bind_text(lambda w=payload_button: w.configure(text=self._t("payload_select")))
        clear_button = ttk.Button(
            payload_buttons,
            text=self._t("payload_clear"),
            command=self._clear_payloads,
            style="Toolbar.TButton",
        )
        clear_button.grid(row=0, column=1, sticky="w")
        self._bind_text(lambda w=clear_button: w.configure(text=self._t("payload_clear")))

        output_label = ttk.Label(
            fields,
            text=self._t("output_label"),
            style="FieldLabel.TLabel",
        )
        output_label.grid(row=7, column=0, sticky="w")
        self._bind_text(lambda w=output_label: w.configure(text=self._t("output_label")))
        output_hint = ttk.Label(
            fields,
            text=self._t("output_hint"),
            style="TLabel",
        )
        output_hint.grid(row=8, column=0, sticky="w", pady=(2, 0))
        self._bind_text(lambda w=output_hint: w.configure(text=self._t("output_hint")))
        self.output_var = tk.StringVar()
        output_entry = ttk.Entry(fields, textvariable=self.output_var, width=48, style="Modern.TEntry")
        output_entry.grid(row=9, column=0, sticky="we", pady=(4, 10))
        self.output_indicator = self._create_indicator(fields)
        self.output_indicator.grid(row=9, column=2, padx=(8, 0))
        output_button = ttk.Button(
            fields, text=self._t("output_rename"), command=self._select_output, style="Toolbar.TButton"
        )
        output_button.grid(row=9, column=1, padx=(8, 0), sticky="e")
        self._bind_text(lambda w=output_button: w.configure(text=self._t("output_rename")))

        self.embed_button = ttk.Button(
            fields, text=self._t("embed_action"), command=self._handle_embed, style="Primary.TButton", state=tk.DISABLED
        )
        self.embed_button.grid(row=10, column=0, columnspan=2, pady=(16, 0), sticky="ew")
        self._bind_text(lambda w=self.embed_button: w.configure(text=self._t("embed_action")))

        self.embed_status = ttk.Label(fields, text="", style="Status.TLabel")
        self.embed_status.grid(row=11, column=0, columnspan=2, pady=(12, 0), sticky="w")

        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(2, weight=0)

    def _build_extract_tab(self) -> None:
        fields = ttk.Frame(self.extract_tab, style="CardInner.TFrame")
        fields.grid(row=0, column=0, sticky="nsew")
        self.extract_tab.columnconfigure(0, weight=1)

        stego_label = ttk.Label(fields, text=self._t("stego_label"), style="FieldLabel.TLabel")
        stego_label.grid(row=0, column=0, sticky="w")
        self._bind_text(lambda w=stego_label: w.configure(text=self._t("stego_label")))
        stego_hint = ttk.Label(
            fields,
            text=self._t("stego_hint"),
            style="TLabel",
        )
        stego_hint.grid(row=1, column=0, sticky="w", pady=(2, 0))
        self._bind_text(lambda w=stego_hint: w.configure(text=self._t("stego_hint")))
        self.stego_var = tk.StringVar()
        stego_entry = ttk.Entry(fields, textvariable=self.stego_var, width=48, style="Modern.TEntry")
        stego_entry.grid(row=2, column=0, sticky="we", pady=(4, 10))
        self.stego_indicator = self._create_indicator(fields)
        self.stego_indicator.grid(row=2, column=2, padx=(8, 0))
        stego_button = ttk.Button(
            fields, text=self._t("browse"), command=self._select_stego, style="Toolbar.TButton"
        )
        stego_button.grid(row=2, column=1, padx=(8, 0), sticky="e")
        self._bind_text(lambda w=stego_button: w.configure(text=self._t("browse")))

        output_dir_label = ttk.Label(fields, text=self._t("output_dir_label"), style="FieldLabel.TLabel")
        output_dir_label.grid(row=3, column=0, sticky="w")
        self._bind_text(lambda w=output_dir_label: w.configure(text=self._t("output_dir_label")))
        output_dir_hint = ttk.Label(
            fields,
            text=self._t("output_dir_hint"),
            style="TLabel",
        )
        output_dir_hint.grid(row=4, column=0, sticky="w", pady=(2, 0))
        self._bind_text(lambda w=output_dir_hint: w.configure(text=self._t("output_dir_hint")))
        self.output_dir_var = tk.StringVar()
        output_dir_entry = ttk.Entry(fields, textvariable=self.output_dir_var, width=48, style="Modern.TEntry")
        output_dir_entry.grid(row=5, column=0, sticky="we", pady=(4, 10))
        self.output_dir_indicator = self._create_indicator(fields)
        self.output_dir_indicator.grid(row=5, column=2, padx=(8, 0))
        output_dir_button = ttk.Button(
            fields, text=self._t("output_dir_browse"), command=self._select_output_dir, style="Toolbar.TButton"
        )
        output_dir_button.grid(row=5, column=1, padx=(8, 0), sticky="e")
        self._bind_text(lambda w=output_dir_button: w.configure(text=self._t("output_dir_browse")))

        extract_button = ttk.Button(
            fields, text=self._t("extract_action"), command=self._handle_extract, style="Primary.TButton"
        )
        extract_button.grid(row=6, column=0, columnspan=2, pady=(16, 0), sticky="ew")
        self._bind_text(lambda w=extract_button: w.configure(text=self._t("extract_action")))

        self.extract_status = ttk.Label(fields, text="", style="Status.TLabel")
        self.extract_status.grid(row=7, column=0, columnspan=2, pady=(12, 0), sticky="w")

        fields.columnconfigure(0, weight=1)
        fields.columnconfigure(2, weight=0)

    def _select_carrier(self) -> None:
        path = filedialog.askopenfilename(title=self._t("dialog_carrier_title"))
        if path:
            self.carrier_var.set(path)
            current_output = self.output_var.get().strip()
            if not current_output:
                suggested = self._suggest_output_path(path)
                self.output_var.set(suggested)

    def _select_payloads(self) -> None:
        paths = filedialog.askopenfilenames(title=self._t("dialog_payload_title"))
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
            summary = self._t("payload_summary_none")
        else:
            names = [Path(path).name for path in self.payload_paths]
            count = len(names)
            if count <= 3:
                lines = "\n".join(f"- {name}" for name in names)
                summary = self._t("payload_summary_lines", count=count, lines=lines)
            else:
                displayed = ", ".join(names[:3])
                summary = self._t("payload_summary_many", count=count, displayed=displayed)
        self.payload_summary_var.set(summary)

    def _select_output(self) -> None:
        carrier_path = self.carrier_var.get().strip()
        initial_name = ""
        if carrier_path:
            initial_name = self._suggest_output_path(carrier_path)
        name = simpledialog.askstring(
            self._t("dialog_output_prompt_title"),
            self._t("dialog_output_prompt", output_dir=OUTPUT_DIR),
            initialvalue=initial_name or self._t("default_output_name"),
        )
        if name:
            self.output_var.set(name.strip())

    def _select_stego(self) -> None:
        path = filedialog.askopenfilename(
            title=self._t("dialog_stego_title"),
            initialdir=OUTPUT_DIR,
        )
        if path:
            selected = Path(path).expanduser()
            try:
                selected.relative_to(OUTPUT_DIR)
            except ValueError:
                messagebox.showwarning(
                    self._t("dialog_invalid_location_title"),
                    self._t("dialog_invalid_location_message", output_dir=OUTPUT_DIR),
                )
                return
            self.stego_var.set(str(selected))

    def _select_output_dir(self) -> None:
        path = filedialog.askdirectory(title=self._t("dialog_output_dir_title"))
        if path:
            self.output_dir_var.set(path)

    def _handle_embed(self) -> None:
        carrier = self.carrier_var.get().strip()
        payloads = list(self.payload_paths)
        output = self.output_var.get().strip()

        if not self._valid_flags["carrier"] or not self._valid_flags["payload"] or not self._valid_flags["output"]:
            messagebox.showwarning(
                self._t("fields_incomplete_title"),
                self._t("fields_incomplete_embed_message"),
            )
            return

        self._set_status(self.embed_status, "", success=True)

        try:
            output_path = embed_file(carrier, payloads, output)
        except Exception as exc:  # noqa: BLE001 - on affiche le message à l'utilisateur.
            self._report_error(
                self._t("error_embed_title"),
                self._t("error_embed_message", error=exc),
                self.embed_status,
                exc,
            )
        else:
            if not output_path.exists():
                self._report_error(
                    self._t("error_missing_output_title"),
                    self._t("error_missing_output_message"),
                    self.embed_status,
                    FileNotFoundError(str(output_path)),
                )
                return
            self._set_status(
                self.embed_status,
                self._t("embed_success_status", count=len(payloads), path=output_path),
                success=True,
            )
            messagebox.showinfo(
                self._t("success_title"),
                self._t("embed_success_message", count=len(payloads), path=output_path),
            )

    def _handle_extract(self) -> None:
        stego_path = self.stego_var.get().strip()
        output_dir = self.output_dir_var.get().strip()

        if not stego_path or not output_dir:
            messagebox.showwarning(
                self._t("fields_incomplete_title"),
                self._t("fields_incomplete_extract_message"),
            )
            return

        self._set_status(self.extract_status, "", success=True)

        try:
            extracted_paths = extract_file(stego_path, output_dir)
        except Exception as exc:  # noqa: BLE001 - le message est remonté à l'écran.
            self._report_error(
                self._t("error_extract_title"),
                self._t("error_extract_message", error=exc),
                self.extract_status,
                exc,
            )
        else:
            names = ", ".join(path.name for path in extracted_paths)
            self._set_status(
                self.extract_status,
                self._t("extract_success_status", count=len(extracted_paths), names=names),
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

    def _t(self, key: str, **kwargs) -> str:
        return translate(key, language=self.language, **kwargs)

    def _bind_text(self, callback: Callable[[], None]) -> None:
        self._text_bindings.append(callback)

    def _apply_translations(self) -> None:
        for callback in self._text_bindings:
            callback()

    def _update_language_buttons(self) -> None:
        for lang, button in self._language_buttons.items():
            state = tk.DISABLED if lang == self.language else tk.NORMAL
            button.configure(state=state)

    def _switch_language(self, language: str) -> None:
        if language not in LANGUAGES or language == self.language:
            return
        self.language = language
        global CURRENT_LANGUAGE
        CURRENT_LANGUAGE = language
        self._apply_translations()
        self._update_language_buttons()
        self._update_payload_summary()
        self._refresh_embed_state()
        self._refresh_extract_state()
        self._set_status(self.embed_status, "", success=True)
        self._set_status(self.extract_status, "", success=True)

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
