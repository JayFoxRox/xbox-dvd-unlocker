object Form1: TForm1
  Left = 583
  Top = 72
  Width = 398
  Height = 601
  Caption = 'Unlocker v0.11 by The Specialist'
  Color = clBtnFace
  DefaultMonitor = dmDesktop
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    Left = 16
    Top = 512
    Width = 117
    Height = 13
    Caption = 'Select XBOX DVD drive:'
  end
  object Button1: TButton
    Left = 296
    Top = 512
    Width = 75
    Height = 25
    Caption = 'Unlock drive'
    TabOrder = 0
    OnClick = Button1Click
  end
  object Memo1: TMemo
    Left = 8
    Top = 8
    Width = 369
    Height = 489
    TabOrder = 1
  end
  object DriveComboBox1: TDriveComboBox
    Left = 144
    Top = 512
    Width = 145
    Height = 19
    TabOrder = 2
  end
  object DCP_sha11: TDCP_sha1
    Id = 2
    Algorithm = 'SHA1'
    HashSize = 160
    Left = 248
    Top = 536
  end
end
