# hook-Crypto.py
from PyInstaller.utils.hooks import collect_submodules, collect_data_files

hiddenimports = collect_submodules('Crypto')
datas = collect_data_files('Crypto')