{ XBOX 1 DVD-Drive unlocker tool v0.1 by The Specialist.

This code shows how to unlock the XBOX 1 DVD-drive and how the kernel authentication process works.
Thanks to everybody on www.xboxhacker.net and especially Anita999, Bluecop, loser, MacDennis,
Swolsten and Takires, who supplied very good input. Without it, this tool would not have been
posssible.

* Summary: The XBOX kernel checks if the inserted disc is an 'authentic' XBOX DVD. This 'authentication'
procedure however also 'unlocks' the DVD-drive. If this procedure is succesful, the kernel sets a bit
("IdexCdRomDVDX2Authenticated") to 1 and assumes the DVD is an original XBOX DVD. Also, the
drive is unlocked after this process.

* Authentication process on the drive's site (mainly based on info by Takires)
The drive keeps track of it's 'state'. There are 10 states: 0,1,2,3,4,5,6,A,B,FF. State "FF" is the
'error' state. State 0 is the 'initial' state that the drive in after it's initialized. Also,
if the tray opens, the state is set back to 0. State 'B' is the last state and if this state
is reached, the drive is 'unlocked'. Transisitions between these states are done by 3 different
ATAPI commands: mode sense[10], mode select[10] and read dvd structure.
Transition 0 -> 1 is done by mode sense. Transition 1 -> 2 is done by the 'read dvd structure'
command. Transition 2 -> 3 by mode select. Transition 3 -> 4 by mode sense, Transition 4 -> 5 by
mode select, transition 5 -> 6 by mode sense, transition 6 -> A by mode select and the final
transition A -> B by mode sense.

* Authentication process on the kernel's site:
Like said before, the kernel keeps track of an 'authentication' bit ("IdexCdRomDVDX2Authenticated").
This bit is set to 0 if the kernel initializes and set to 1 if authentication was succesful and
cleared again if the Tray ejects. The routine responsible for authentication is called
"IdexCdRomAuthenticationSequence". The kernel starts with asking for the 'authentication page',
this is done by sending the first mode sense command. Then it asks for the 'control data block'. This
info is received as an answer to the 'read dvd structure' command. The most important data in this
block is the RC4-encrypted challengeresponsetable, a 'hashblock' and a 'signature'.
The challengeresponsetable contains 23 challenge/responses. Some of these challenges are sent to the
drive. The drive has to come up with a response and the kernel checks if the response is the
same as the one in the table.
Most part of this 'control data block' is signed. It verifies the signature by computing a SHA1 hash
for (a part of the) control data block. The challengeresponse table is in this part, so it can't
be changed, or the signature check will fail.
Another check that the kernel does is comparing the 'disc category and version' as returned in
the data that's received after the first mode sense to the 'disc category and version' info in
the control data block (these should both be '$D1'. If these match and the signature for the
control data is correct and the drive answers with the correct responses, then the kernel assumes
that the disc in the drive is an authentic XBOX DVD-ROM disc and sets the
"IdexCdRomDVDX2Authenticated" bit to 1.
Note that the verification of the signature and the comparison of the 'disc category' is not done
in this source. If you'd add it, you'd have the exact same routine as the kernel uses for
authentication.

I've documented this code as much as possible. Everybody's free to copy and change it in any
way they like, but don't forget to give credit to all the people on Xboxhacker who made this possible :)

30 December 2005, The Specialist.
 }
 
unit scsi1;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ComCtrls,  DCPsha1, DCPcrypt2, FileCtrl;

type
  TForm1 = class(TForm)
    Button1: TButton;
    Memo1: TMemo;
    Label1: TLabel;
    DriveComboBox1: TDriveComboBox;
    DCP_sha11: TDCP_sha1;
    procedure Button1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

// the following three types are used for ATAPI communication
type
  PSCSI_PASS_THROUGH = ^SCSI_PASS_THROUGH;
  SCSI_PASS_THROUGH = Record
    Length              : Word;
    ScsiStatus          : Byte;
    PathId              : Byte;
    TargetId            : Byte;
    Lun                 : Byte;
    CdbLength           : Byte;
    SenseInfoLength     : Byte;
    DataIn              : Byte;
    DataTransferLength  : ULONG;
    TimeOutValue        : ULONG;
    DataBufferOffset    : ULONG;
    SenseInfoOffset     : ULONG;
    Cdb                 : Array[0..15] of Byte;
  end;

type
  PSCSI_PASS_THROUGH_DIRECT = ^SCSI_PASS_THROUGH_DIRECT; 
  SCSI_PASS_THROUGH_DIRECT = record 
    Length              : Word; 
    ScsiStatus          : Byte; 
    PathId              : Byte; 
    TargetId            : Byte; 
    Lun                 : Byte; 
    CdbLength           : Byte; 
    SenseInfoLength     : Byte; 
    DataIn              : Byte; 
    DataTransferLength  : ULONG; 
    TimeOutValue        : ULONG; 
    DataBuffer          : Pointer; 
    SenseInfoOffset     : ULONG; 
    Cdb                 : Array[0..15] of Byte; 
  end; 

type
  PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER = ^SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
  SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER = record
    Spt      : SCSI_PASS_THROUGH_DIRECT;
    Filler   : ULONG;
    SenseBuf : Array[0..31] of Byte;
  end;
  
type 
  TRC4Context = record
    D: array[Byte] of Byte; 
    I,J: Byte; 
  end;

var
  Form1: TForm1;
  driveHandle:Thandle;
  rc4key: TRC4Context;
  scsibuffer: Array[0..2000] of Byte;

implementation

{$R *.dfm}

// to be able to send ATAPI commands to a drive, we first have to 'open' it:
function OpenDrive: THandle;
begin 
  Result := CreateFile( PChar('\\.\'+ form1.drivecombobox1.Drive+':'),
                        GENERIC_READ Or GENERIC_WRITE,
                        FILE_SHARE_READ Or FILE_SHARE_WRITE, 
                        Nil, 
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, 
                        0); 
end; 

//and the routine to close it after everything is done:
function CloseDrive(Const AHandle: THandle):Boolean;
begin 
  Result := CloseHandle(AHandle); 
end;

{This is a 'standard' RC4 decryption routine, as you can find them anywhere
on the net. I've copied this thing from http://www.delphipraxis.net/topic30830_rc4verschluesselung.html
It's used to calculate the RC4 key to decrypt the challengeresponsetable with. Only thing
I changed in it is that I've set the size to '7', which is what the kernel also does ;)
More on the decryption later
}
procedure RC4Init(var RC4: TRC4Context; const Key: String);
var
  R,S,T,K: Byte;
  U,L: Integer;
begin
  L := 7;//Length(Key);
  with RC4 do
  begin
    I := 0;
    J := 0;
    for S := 0 to 255 do D[S] := S;
    R := 0;
    U := 0;
    for S := 0 to 255 do
    begin
      if U < L then K := PByteArray(Key)[U] else K := 0;
      Inc(U);
      if U >= L then U := 0;

      Inc(R, D[S] + K);
      T    := D[S];
      D[S] := D[R];
      D[R] := T;
    end;
  end;
end;
procedure rc4Decrypt(const InData; var OutData; Size: longword);
var
  i, j, t, k: longword;
begin
  i:= 0; j:= 0;
  for k:= 0 to Size-1 do
  begin
    i:= (i + 1) and $FF;
    t:= rc4key.D[i];
    j:= (j + t) and $FF;
    rc4key.D[i]:= rc4key.D[j];
    rc4key.D[j]:= t;
    t:= (t + rc4key.D[i]) and $FF;
    Pbytearray(@OutData)^[k]:= Pbytearray(@InData)^[k] xor rc4key.D[t];
  end;
end;

//just a small routine to output formatted text to the memo box on the form.
procedure outputdata;
var
  j: integer;
begin;
 For j:=0 to 2 DO
  form1.memo1.lines.add (
   inttohex (scsibuffer[j*16],2)+' '+
   inttohex (scsibuffer[j*16+1],2)+' '+
   inttohex (scsibuffer[j*16+2],2)+' '+
   inttohex (scsibuffer[j*16+3],2)+' '+
   inttohex (scsibuffer[j*16+4],2)+' ' +
   inttohex (scsibuffer[j*16+5],2)+' '+
   inttohex (scsibuffer[j*16+6],2)+' '+
   inttohex (scsibuffer[j*16+7],2)+' - '+
   inttohex (scsibuffer[j*16+8],2)+' '+
   inttohex (scsibuffer[j*16+9],2)+' '+
   inttohex (scsibuffer[j*16+10],2)+' '+
   inttohex (scsibuffer[j*16+11],2)+' '+
   inttohex (scsibuffer[j*16+12],2)+' '+
   inttohex (scsibuffer[j*16+13],2)+' ' +
   inttohex (scsibuffer[j*16+14],2)+' '+
   inttohex (scsibuffer[j*16+15],2) );
end;

//The main routine.
procedure UnlockDrive(const AHandle:THandle);
var 
  SPTDW : SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;
  Size, Returned : LongWord;
  i,k,l:integer;
  chalpos: array [0..10] of integer;
  restable: array [0..260] of byte;
  hash: array [0..$2b] of byte;
  shadigest: array [0..54] of byte;
  shastring: string;
begin
    { Initialization of the first  ATAPI command to be sent. The actual data it sends
    is the 'cdb' data. I started this program by sending a 'read capacity' ATAPI command. This
    is not necessary for the unlocking process, but the returned data shows the partition size
    and it's nice to see what the initial parition size was before unlocking  :)
    }
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; // = SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28;
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $25;  //The first byte of the packet is always the opcode. $25=read capacity
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $00;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $00;
  SPTDW.Spt.Cdb[9] := $00;


{actual sending of the ATAPI command is done with the 'deviceiocontrol API. $4D014 is the value
for " IOCTL_SCSI_PASS_THROUGH_DIRECT"}
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
     form1.memo1.lines.add ('Read capacity io succesful. Returned data ->');
  outputdata;

  // Next, continu with sending a 'mode sense' ATAPI command
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; // = SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28;
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $5a; //opcode for 'mode sense'
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $3e; //page code, this informs the drive what this packet is all about. In this case
  SPTDW.Spt.Cdb[3] := $00; // it is $3e, which means that this is a 'authentication related' packet'
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c; //this sets a maximum length to the datablock the drive should return
  SPTDW.Spt.Cdb[9] := $00;
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
      form1.memo1.lines.add ('Mode sense io succesful. Returned data ->')
    ELSE
    begin
      showmessage ('Fatal error, IO failure while sending 1st mode sense');
      exit;
    end;
  outputdata;

  //step 3: read dvd struct
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 12;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; //SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := $664; // control block is $664 bytes long
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $AD; //opcode for 'read dvd structure'
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $ff; //adress on disc specified by these 4 bytes
  SPTDW.Spt.Cdb[3] := $02;
  SPTDW.Spt.Cdb[4] := $fd;
  SPTDW.Spt.Cdb[5] := $ff;
  SPTDW.Spt.Cdb[6] := $fe; //layer number
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $06; //these 2 bytes set the length to $664
  SPTDW.Spt.Cdb[9] := $64;
  SPTDW.Spt.Cdb[10] :=$00;
  SPTDW.Spt.Cdb[11] :=$c0; //control code, is used to specify what kind of command this is. $C0 tells the drive that the xbox wants the control block for the xbox partition
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Read DVD structure IO succesful. Returned data (only first few bytes) ->') ELSE
    begin
    showmessage ('Fatal error, IO failure while sending read dvd struct');
    exit;
    end;
  outputdata;

  {byte 772 in the returned control block should ALWAYS be 1. Byte 773 contains the number
  of challenge/responses in the challenge/response table}

  IF  ((scsibuffer[772] <> 1) OR (scsibuffer[773] = 0)) THEN
    begin
    showmessage ('fatal error, invalid host challenge response table');
    exit;
    end;
  form1.Memo1.lines.add ('Number of entries in challenge responste table = '+inttostr(scsibuffer[773]));

{now the xbox is going to decrypt the challengereponse table (and so should we, hehe).
This procedure contains a standard SHA1 and standard RC4 routine, you can find anywhere on the net.
I've used an open source Delphi component for the SHA1, you can download it at:
http://www.devarchive.com/f621.html.

Now, the xbox first calculates a SHA1 'digest' for $2c bytes in the control block, starting at $4a3.
It uses this digest to calculate a RC4 key to decrypt the table with
}
  for i:=0 to $2b DO
    hash[i]:=scsibuffer[i+$4a3];
//calculate digest
  form1.DCP_sha11.Init;
  form1.DCP_sha11.Update(hash,$2c);  //size = $2c
  form1.DCP_sha11.Final (shadigest);
//use the calculated digest as a string input for the Rc4 routine
  shastring:='';
  for i:=0 to 54 do
    shastring:=shastring+chr(shadigest[i]);
  RC4Init(rc4key,shastring);
  for i:=0 to 260 DO
    restable[i]:=scsibuffer[774+i];
  rc4decrypt (restable, restable, $FD); //overwrite unencrypted data with encrypted data. Size = $FD

{the table is now decrypted. The 23 entries in this table are each 11 bytes long ->
1st byte = some sort of identifier. The xbox only uses challenges that have this identifier
set to 1 (there are only a few).
2nd byte = Challenge ID
bytes 3,4,5,6 are the actual challenge
byte 7 is the 'response ID'
bytes 8,9,10,11 are the actual responses
}

//now we create a table with only challenge/responses that have the identifier set to 1, because
//these are the ones the kernel uses and so should we ;)

  k:=0;
  For l:=0 to 23 DO
    IF  restable[l*11]=1 THEN
      begin
      chalpos[k]:=l;
      k:=k+1;
      end;
  IF k < 2 THEN  //there should be at least 2 challenges with identifier=1 to send.
    begin
    showmessage ('Fatal Error: Not enough usable challenge/responses found in table !');
    exit;
    end;

{Now we're going to issue the first challenge to the drive. We're only going to send 2 different
challenges -> the last 2 challenges in the table -> k-2 and k-1.
The xbox might send more, but this is at random. 2 is all you need. It however always sends the last
2 challenges}

//step 4: mode select
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 0; //0 = SCSI_IOCTL_DATA_OUT
  SPTDW.Spt.DataTransferLength := 28;
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $55;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $00;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;

  scsibuffer[1]:= $1A;  // length of total packet
  scsibuffer[8]:= $3E; // the 'page code'
  scsibuffer[9]:= $12; //page length
  scsibuffer[11]:=$01; //should always be 1.
  scsibuffer[13]:=$D1; //disc category and version
  scsibuffer[14]:=$01; //should always be 1.
  scsibuffer[15]:=restable[1+chalpos[k-2]*11]; //challenge ID
  scsibuffer[16]:=restable[2+chalpos[k-2]*11]; //actual challenge
  scsibuffer[17]:=restable[3+chalpos[k-2]*11];
  scsibuffer[18]:=restable[4+chalpos[k-2]*11];
  scsibuffer[19]:=restable[5+chalpos[k-2]*11];

  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode select IO succesful') ELSE
      begin
      showmessage ('Fatal error, IO failure while sending mode select');
      exit;
      end;

  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);

   // step 5: mode sense
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; //SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $5a;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $3e;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode sense io succesful. Returned data -> ') ELSE
        begin
    showmessage ('Fatal error, IO failure while sending mode sense');
    exit;
    end;
  outputdata;

//step 6: mode select
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 0; //SCSI_IOCTL_DATA_OUT; !!!
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $55;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $00;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;

  scsibuffer[1]:= $1A;
  scsibuffer[8]:= $3E;
  scsibuffer[9]:= $12;
  scsibuffer[11]:=$01;
  scsibuffer[12]:=$01; //this must now be set to 1
  scsibuffer[13]:=$D1;
  scsibuffer[14]:=$01;
  scsibuffer[15]:=restable[1+chalpos[k-1]*11];
  scsibuffer[16]:=restable[2+chalpos[k-1]*11];
  scsibuffer[17]:=restable[3+chalpos[k-1]*11];
  scsibuffer[18]:=restable[4+chalpos[k-1]*11];
  scsibuffer[19]:=restable[5+chalpos[k-1]*11];
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode select IO succesful');

   // step 7: mode sense
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; //SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $5a;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $3e;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode sense io succesful. Returned data ->') ELSE
    begin
    showmessage ('Fatal error, IO failure while sending mode sense');
    exit;
    end;;
  outputdata;

//step 8: mode select -> we should now issue the SAME challenge as before, BUT this
//time indicate partition '1' by setting byte $10 in the packet to 1.
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 0; //SCSI_IOCTL_DATA_OUT; !!!
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $55;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $00;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;
  scsibuffer[1]:= $1A;
  scsibuffer[8]:= $3E;
  scsibuffer[9]:= $12;
  scsibuffer[10]:=$01; //partition should now be set to 1
  scsibuffer[11]:=$01;
  scsibuffer[12]:=$01;
  scsibuffer[13]:=$D1;
  scsibuffer[14]:=$01;
  scsibuffer[15]:=restable[1+chalpos[k-1]*11];
  scsibuffer[16]:=restable[2+chalpos[k-1]*11];
  scsibuffer[17]:=restable[3+chalpos[k-1]*11];
  scsibuffer[18]:=restable[4+chalpos[k-1]*11];
  scsibuffer[19]:=restable[5+chalpos[k-1]*11];
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode select IO succesful') ELSE
        begin
    showmessage ('Fatal error, IO failure while sending mode select');
    exit;
    end;

// step 9: mode sense
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH); //_DIRECT ??
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; //SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $5a;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $3e;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $1c;
  SPTDW.Spt.Cdb[9] := $00;
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
    form1.memo1.lines.add ('Mode sense io succesful. Returned data ->') ELSE
        begin
    showmessage ('Fatal error, IO failure while sending mode sense');
    exit;
    end;;
  outputdata;

  {And finally send the 'Read capacity' command. This is not necessary for authentication,
  but I did it as a check to see if everything worked out :) }
  
  ZeroMemory(@SPTDW, SizeOf(SPTDW));
  ZeroMemory (@scsibuffer,2000);
  Size := SizeOf(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER);
  SPTDW.Spt.Length             := SizeOf(SCSI_PASS_THROUGH);
  SPTDW.Spt.CdbLength          := 10;
  SPTDW.Spt.SenseInfoLength    := 32;
  SPTDW.Spt.DataIn             := 1; //SCSI_IOCTL_DATA_IN;
  SPTDW.Spt.DataTransferLength := 28; //SizeOf(scsibuffer);
  SPTDW.Spt.TimeOutValue       := 120;
  SPTDW.Spt.DataBuffer         := @scsibuffer;
  SPTDW.Spt.SenseInfoOffset    := 48;
  SPTDW.Spt.Cdb[0] := $25;
  SPTDW.Spt.Cdb[1] := $00;
  SPTDW.Spt.Cdb[2] := $00;
  SPTDW.Spt.Cdb[3] := $00;
  SPTDW.Spt.Cdb[4] := $00;
  SPTDW.Spt.Cdb[5] := $00;
  SPTDW.Spt.Cdb[6] := $00;
  SPTDW.Spt.Cdb[7] := $00;
  SPTDW.Spt.Cdb[8] := $00;
  SPTDW.Spt.Cdb[9] := $00;
  if DeviceIoControl( AHandle, $4D014, @SPTDW, Size, @SPTDW, Size, Returned, Nil) then
     form1.memo1.lines.add ('Read capacity io succesful. Returned data ->');
  outputdata;

  form1.memo1.lines.add ('');
  IF (scsibuffer[1]) > 0 THEN
   form1.memo1.lines.add ('Reported capacity bigger than standard xbox video partition. Unlocking seems to be succesful !') ELSE
     form1.memo1.lines.add ('Reported small partition size, unlocking probably unsuccesful ');
end;

procedure TForm1.Button1Click(Sender: TObject);
begin
  memo1.Lines.Clear ;
  DriveHandle:=(Opendrive);
  IF DriveHandle = INVALID_HANDLE_VALUE THEN
    begin
    showmessage ('Fatal Error, invalid drive');
    exit;
    end;
  UnlockDrive (DriveHandle);
  CloseDrive(DriveHandle);
end;

end.
