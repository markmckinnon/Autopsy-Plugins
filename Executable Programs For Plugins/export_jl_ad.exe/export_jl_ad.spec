# -*- mode: python -*-

block_cipher = None


a = Analysis(['export_jl_ad.py'],
             pathex=,
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
          a.binaries + [('liblnk.dll','liblnk.dll', 'BINARY'), ('libolecf.dll','libolecf.dll', 'BINARY'), ('msvcr120.dll','c:\\windows\\system32\\msvcr120.dll','BINARY')],
          a.zipfiles,
          a.datas + [('Jump_List_App_Ids.db3','Jump_List_App_Ids.db3', 'BINARY')],
          name='export_jl_ad',
          debug=False,
          strip=False,
          upx=True,
          console=True )
