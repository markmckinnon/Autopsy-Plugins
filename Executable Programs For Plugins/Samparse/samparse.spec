# -*- mode: python -*-

block_cipher = None


a = Analysis(['samparse.py'],
             pathex=['C:\\Users\\Forensic_User\\OneDrive\\Code\\Python_Scripts\\Registry'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries + [('libregf.dll','libregf.dll', 'BINARY'), ('msvcr120.dll','c:\\windows\\system32\\msvcr120.dll','BINARY')],
          a.zipfiles,
          a.datas,
          name='samparse',
          debug=False,
          strip=False,
          upx=True,
          console=True )
