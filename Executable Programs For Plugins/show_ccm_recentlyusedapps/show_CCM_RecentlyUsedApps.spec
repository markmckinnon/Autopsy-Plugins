# -*- mode: python -*-
#
#  Pyinstaller spec file
#
#  For the pathex file add your current directory where the python script resides
#
#  For the a.binaries, this has been added so that the Windows 10 libaries are added
#

block_cipher = None


a = Analysis(['show_ccm_recentlyusedapps.py'],
             pathex=None,
             binaries=None,
             datas=None,
             hiddenimports=None,
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
          a.binaries + [('msvcr120.dll','c:\\windows\\system32\\msvcr120.dll','BINARY')],
          a.zipfiles,
          a.datas,
          name='show_ccm_recentlyusedapps',
          debug=False,
          strip=False,
          upx=True,
          console=True )
