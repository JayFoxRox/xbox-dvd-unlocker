program scsi;

uses
  Forms,
  scsi1 in 'scsi1.pas' {Form1};

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'Unlocker';
  Application.CreateForm(TForm1, Form1);
  Application.Run;
end.
