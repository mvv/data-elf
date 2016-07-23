{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE TypeSynonymInstances #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module provides ELF data structures and (de)serialization routines.
module Data.Elf
  (
  -- * File class
    FileClass(..)
  , invalidFileClass
  , elf32FileClass
  , elf64FileClass
  , IsFileClass(..)
  , Elf32(..)
  , anElf32
  , Elf64(..)
  , anElf64
  -- * File header
  -- ** File type
  , FileType(..)
  , noneFileType
  , relFileType
  , execFileType
  , dynFileType
  , coreFileType
  , loOsFileType
  , hiOsFileType
  , loProcFileType
  , hiProcFileType
  -- ** Machine code
  , Machine(..)
  , undefMachine
  , i386Machine
  , amd64Machine
  -- ** Machine flags
  , MachFlags(..)
  -- ** ELF version
  , Version(..)
  , invalidVersion
  , firstVersion
  -- ** Data encoding
  , DataEnc(..)
  , invalidDataEnc
  , lsbDataEnc
  , msbDataEnc
  -- ** Operating system ABI
  , OsAbi(..)
  , sysvOsAbi
  , hpuxOsAbi
  , netBsdOsAbi
  , gnuOsAbi
  , solarisOsAbi
  , aixOsAbi
  , irixOsAbi
  , freeBsdOsAbi
  , tru64OsAbi
  , modestoOsAbi
  , openBsdOsAbi
  , openVmsOsAbi
  , nskOsAbi
  , arosOsAbi
  , fenixOsAbi
  , embedOsAbi
  , AbiVer(..)
  , undefAbiVer
  -- ** Identification
  , Ident(..)
  , anIdent
  -- ** File header
  , FileHdr(..)
  , FileHdr32
  , aFileHdr32
  , FileHdr64
  , aFileHdr64
  -- * Program header
  -- ** Segment type
  , SegType(..)
  , unusedSegType
  , loadSegType
  , dynSegType
  , interpSegType
  , noteSegType
  , shlibSegType
  , phdrSegType
  , loOsSegType
  , hiOsSegType
  , loProcSegType
  , hiProcSegType
  -- ** Segment flags
  , SegFlags(..)
  , execSegFlag
  , writeSegFlag
  , readSegFlag
  , osSegFlags
  , procSegFlags
  -- ** Program header
  , ProgHdr(..)
  , ProgHdr32
  , aProgHdr32
  , ProgHdr64
  , aProgHdr64
  -- * Section header
  -- ** String table index
  , StrIx
  -- ** Section header table index
  , SecIx(..)
  , undefSecIx
  , lastSecIx
  , loOsSecIx
  , hiOsSecIx
  , loProcSecIx
  , hiProcSecIx
  , absSecIx
  , commonSecIx
  , xIndexSecIx
  -- ** Section type
  , SecType(..)
  , unusedSecType
  , progBitsSecType
  , symSecType
  , strSecType
  , relaSecType
  , hashSecType
  , dynSecType
  , noteSecType
  , noBitsSecType
  , relSecType
  , shlibSecType
  , dynSymSecType
  , loOsSecType
  , hiOsSecType
  , loProcSecType
  , hiProcSecType
  -- ** Section flags
  , SecFlags(..)
  , writeSecFlag
  , allocSecFlag
  , execSecFlag
  , mergeSecFlag
  , infoLinkSecFlag
  , osSecFlags
  , procSecFlags
  -- ** Section header
  , SecHdr(..)
  , SecHdr32
  , aSecHdr32
  , SecHdr64
  , aSecHdr64
  , zeroSecHdr
  -- * Symbol table
  -- ** Symbol type
  , SymType(..)
  , undefSymType
  , objSymType
  , funSymType
  , secSymType
  , fileSymType
  , commonSymType
  , tlsSymType
  , loOsSymType
  , hiOsSymType
  , loProcSymType
  , hiProcSymType
  -- ** Symbol binding
  , SymBind(..)
  , localSymBind
  , globalSymBind
  , weakSymBind
  , loOsSymBind
  , hiOsSymBind
  , loProcSymBind
  , hiProcSymBind
  -- ** Symbol visibility
  , SymVisi(..)
  , defSymVisi
  , intSymVisi
  , hiddenSymVisi
  , protSymVisi
  , exportSymVisi
  , singSymVisi
  , elimSymVisi
  -- ** Symbol table index
  , SymIx(..)
  , undefSymIx
  -- ** Symbol table entry
  , SymEnt(..)
  , SymEnt32
  , aSymEnt32
  , SymEnt64
  , aSymEnt64
  , zeroSymEnt
  -- * Relocation table
  -- ** Relocation type
  , RelType(..)
  , RelType32
  , RelType64
  -- ** Relocation table entry
  , RelEnt(..)
  , RelEnt32
  , aRelEnt32
  , RelEnt64
  , aRelEnt64
  , RelaEnt(..)
  , RelaEnt32
  , aRelaEnt32
  , RelaEnt64
  , aRelaEnt64
  ) where

import Data.Typeable (Typeable)
import Data.Data (Data)
import Data.Proxy (Proxy(..))
import Data.Ix (Ix)
import Data.Bits (Bits, shiftL, shiftR, (.|.), FiniteBits)
import Data.Flags (Flags(noFlags), BoundedFlags)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.ShortWord (Word4, Word24)
import Data.Monoid ((<>))
import Data.Serializer (Serializable, SizedSerializable)
import qualified Data.Serializer as S
import Data.Deserializer (Deserializable, (<?>))
import qualified Data.Deserializer as D
import Control.Applicative ((<$>))
import Control.Monad (void, unless)

-- | File class.
newtype FileClass = FileClass { unFileClass ∷ Word8 }
                    deriving (Typeable, Data, Show, Read,
                              Eq, Ord, Bounded, Enum, Ix)

-- | Invalid class (@ELFCLASSNONE@).
invalidFileClass ∷ FileClass
invalidFileClass = FileClass 0

-- | ELF32 class (@ELFCLASS32@).
elf32FileClass ∷ FileClass
elf32FileClass = FileClass 1

-- | ELF64 class (@ELFCLASS64@).
elf64FileClass ∷ FileClass
elf64FileClass = FileClass 2

-- | File class type-level index.
class (Typeable c,
       Typeable (Addr c), Data (Addr c),
       Typeable (Off c), Data (Off c),
       Typeable (UnSymIx c), Data (UnSymIx c),
       Typeable (UnRelType c), Data (UnRelType c),
       Show (Addr c), Read (Addr c),
       Show (Off c), Read (Off c),
       Show (UnSymIx c), Read (UnSymIx c),
       Show (UnRelType c), Read (UnRelType c),
       Eq (Addr c), Ord (Addr c), Bounded (Addr c), Enum (Addr c),
       Num (Addr c), Integral (Addr c), Real (Addr c),
       Bits (Addr c), FiniteBits (Addr c),
       Eq (Off c), Ord (Off c), Bounded (Off c), Enum (Off c),
       Num (Off c), Integral (Off c), Real (Off c),
       Bits (Off c), FiniteBits (Off c),
       Eq (UnSymIx c), Ord (UnSymIx c), Bounded (UnSymIx c), Enum (UnSymIx c),
       Ix (UnSymIx c), Num (UnSymIx c), Integral (UnSymIx c),
       Real (UnSymIx c), Bits (UnSymIx c), FiniteBits (UnSymIx c),
       Eq (UnRelType c), Ord (UnRelType c), Bounded (UnRelType c),
       Enum (UnRelType c), Ix (UnRelType c))
      ⇒ IsFileClass c where
  type Addr c
  type Off c
  type UnSymIx c
  type UnRelType c
  fileClass ∷ Proxy c → FileClass

-- | 32-bit ELF class type-level index.
data Elf32 = Elf32 deriving (Typeable, Data)

-- | 'Elf32' proxy value.
anElf32 ∷ Proxy Elf32
anElf32 = Proxy

instance IsFileClass Elf32 where
  type Addr Elf32 = Word32
  type Off Elf32 = Word32
  type UnSymIx Elf32 = Word24
  type UnRelType Elf32 = Word8
  fileClass _ = elf32FileClass

-- | 64-bit ELF class type-level index.
data Elf64 = Elf64 deriving (Typeable, Data)

-- | 'Elf64' proxy value.
anElf64 ∷ Proxy Elf64
anElf64 = Proxy

instance IsFileClass Elf64 where
  type Addr Elf64 = Word64
  type Off Elf64 = Word64
  type UnSymIx Elf64 = Word32
  type UnRelType Elf64 = Word32
  fileClass _ = elf64FileClass

-- | File type.
newtype FileType = FileType { unFileType ∷ Word16 }
                   deriving (Typeable, Data, Show, Read,
                             Eq, Ord, Bounded, Enum, Ix)

-- | No file type (@ET_NONE@).
noneFileType ∷ FileType
noneFileType = FileType 0

-- | Relocatable object file (@ET_REL@).
relFileType ∷ FileType
relFileType = FileType 1

-- | Executable file (@ET_EXEC@).
execFileType ∷ FileType
execFileType = FileType 2

-- | Shared object file (@ET_DYN@).
dynFileType ∷ FileType
dynFileType = FileType 3

-- | Core file (@ET_CORE@).
coreFileType ∷ FileType
coreFileType = FileType 4

-- | First environment-specific type (@ET_LOOS@).
loOsFileType ∷ FileType
loOsFileType = FileType 0xFE00

-- | Last environment-specific type (@ET_HIOS@).
hiOsFileType ∷ FileType
hiOsFileType = FileType 0xFEFF

-- | First processor-specific type (@ET_LOPROC@).
loProcFileType ∷ FileType
loProcFileType = FileType 0xFF00

-- | Last processor-specific type (@ET_HIPROC@).
hiProcFileType ∷ FileType
hiProcFileType = FileType 0xFFFF

-- | Machine architecture.
newtype Machine = Machine { unMachine ∷ Word16 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | No machine (@EM_NONE@).
undefMachine ∷ Machine
undefMachine = Machine 0

-- | Intel 80386 (@EM_386@).
i386Machine ∷ Machine
i386Machine = Machine 3

-- | AMD x86-64 (@EM_X86_64@).
amd64Machine ∷ Machine
amd64Machine = Machine 62

-- | Architecture-specific flags.
newtype MachFlags = MachFlags { unMachFlags ∷ Word32 }
                    deriving (Typeable, Data, Show, Read,
                              Eq, Flags, BoundedFlags)

-- | ELF version.
newtype Version = Version { unVersion ∷ Word8 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)
-- | Invalid version.
invalidVersion ∷ Version
invalidVersion = Version 0

-- | Version 1.
firstVersion ∷ Version
firstVersion = Version 1

-- | Data encoding.
newtype DataEnc = DataEnc { unDataEnc ∷ Word8 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Invalid data encoding.
invalidDataEnc ∷ DataEnc
invalidDataEnc = DataEnc 0

-- | Little-endian data encoding (@ELFDATA2LSB@).
lsbDataEnc ∷ DataEnc
lsbDataEnc = DataEnc 1

-- | Big-endian data encoding (@ELFDATA2MSB@).
msbDataEnc ∷ DataEnc
msbDataEnc = DataEnc 2

-- | System ABI.
newtype OsAbi = OsAbi { unOsAbi ∷ Word8 }
                deriving (Typeable, Data, Show, Read,
                          Eq, Ord, Bounded, Enum, Ix)

-- | System V (@ELFOSABI_NONE@).
sysvOsAbi ∷ OsAbi
sysvOsAbi = OsAbi 0

-- | HP-UX (@ELFOSABI_HPUX@).
hpuxOsAbi ∷ OsAbi
hpuxOsAbi = OsAbi 1

-- | NetBSD (@ELFOSABI_NETBSD@).
netBsdOsAbi ∷ OsAbi
netBsdOsAbi = OsAbi 2

-- | GNU (@ELFOSABI_GNU@, @ELFOSABI_LINUX@).
gnuOsAbi ∷ OsAbi
gnuOsAbi = OsAbi 3

-- | Solaris (@ELFOSABI_SOLARIS@).
solarisOsAbi ∷ OsAbi
solarisOsAbi = OsAbi 6

-- | AIX (@ELFOSABI_AIX@).
aixOsAbi ∷ OsAbi
aixOsAbi = OsAbi 7

-- | IRIX (@ELFOSABI_IRIX@).
irixOsAbi ∷ OsAbi
irixOsAbi = OsAbi 8

-- | FreeBSD (@ELFOSABI_FREEBSD@).
freeBsdOsAbi ∷ OsAbi
freeBsdOsAbi = OsAbi 9

-- | Tru64 UNIX (@ELFOSABI_TRU64@).
tru64OsAbi ∷ OsAbi
tru64OsAbi = OsAbi 10

-- | Novell Modesto (@ELFOSABI_MODESTO@).
modestoOsAbi ∷ OsAbi
modestoOsAbi = OsAbi 11

-- | OpenBSD (@ELFOSABI_OPENBSD@).
openBsdOsAbi ∷ OsAbi
openBsdOsAbi = OsAbi 12

-- | OpenVMS (@ELFOSABI_OPENVMS@).
openVmsOsAbi ∷ OsAbi
openVmsOsAbi = OsAbi 13

-- | Hewlett-Packard Non-Stop Kernel (@ELFOSABI_NSK@).
nskOsAbi ∷ OsAbi
nskOsAbi = OsAbi 14

-- | Amiga Research OS (@ELFOSABI_AROS@).
arosOsAbi ∷ OsAbi
arosOsAbi = OsAbi 15

-- | FenixOS (@ELFOSABI_FENIXOS@).
fenixOsAbi ∷ OsAbi
fenixOsAbi = OsAbi 16

-- | Standalone (embedded) application.
embedOsAbi ∷ OsAbi
embedOsAbi = OsAbi 255

-- | ABI version.
newtype AbiVer = AbiVer { unAbiVer ∷ Word8 }
                 deriving (Typeable, Data, Show, Read,
                           Eq, Ord, Bounded, Enum, Ix)

-- | Undefined ABI version.
undefAbiVer ∷ AbiVer
undefAbiVer = AbiVer 0

-- | Identification.
data Ident = Ident { idClass   ∷ FileClass
                   , idVersion ∷ Version
                   , idDataEnc ∷ DataEnc
                   , idOsAbi   ∷ OsAbi
                   , idAbiVer  ∷ AbiVer }
             deriving (Typeable, Data, Show, Read, Eq)

-- | 'Ident' proxy value.
anIdent ∷ Proxy Ident
anIdent = Proxy

instance Serializable Ident where
  put (Ident {..})
    =  S.byteString "\127ELF"
    <> S.word8 (unFileClass idClass)
    <> S.word8 (unDataEnc idDataEnc)
    <> S.word8 (unVersion idVersion)
    <> S.word8 (unOsAbi idOsAbi)
    <> S.word8 (unAbiVer idAbiVer)
    <> S.byteString "\0\0\0\0\0\0\0"

instance SizedSerializable Ident where
  size _ = 16
  {-# INLINE size #-}

instance Deserializable Ident where
  get = do
    void $ D.bytes "\127ELF" <?> "ELF magic number"
    fileCls ← FileClass <$> D.word8 <?> "file class"
    dataEnc ← DataEnc <$> D.word8 <?> "data encoding"
    version ← Version <$> D.word8 <?> "file version"
    osAbi   ← OsAbi <$> D.word8 <?> "OS ABI code"
    abiVer  ← AbiVer <$> D.word8 <?> "OS ABI version"
    D.skip 7
    return $ Ident { idClass   = fileCls
                   , idDataEnc = dataEnc
                   , idVersion = version
                   , idOsAbi   = osAbi
                   , idAbiVer  = abiVer }

-- | File header.
data FileHdr c = FileHdr { fhType    ∷ FileType
                         , fhMachine ∷ Machine
                         , fhEntry   ∷ Addr c
                         , fhFlags   ∷ MachFlags
                         , fhPhOff   ∷ Off c
                         , fhPhNum   ∷ Word16
                         , fhShOff   ∷ Off c
                         , fhShNum   ∷ Word16
                         , fhSnStIx  ∷ SecIx }
                 deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (FileHdr c)
deriving instance IsFileClass c ⇒ Show (FileHdr c)
deriving instance IsFileClass c ⇒ Read (FileHdr c)
deriving instance IsFileClass c ⇒ Eq (FileHdr c)

-- | ELF32 file header.
type FileHdr32 = FileHdr Elf32

-- | 'FileHdr32' proxy value.
aFileHdr32 ∷ Proxy FileHdr32
aFileHdr32 = Proxy

instance Serializable FileHdr32 where
  put (FileHdr {..}) 
    =  S.word16 (unFileType fhType)
    <> S.word16 (unMachine fhMachine)
    <> S.word32 1
    <> S.word32 fhEntry
    <> S.word32 fhPhOff
    <> S.word32 fhShOff
    <> S.word32 (unMachFlags fhFlags)
    <> S.word16 (fromIntegral $ S.size anIdent + S.size aFileHdr32)
    <> S.word16 (fromIntegral $ S.size aProgHdr32)
    <> S.word16 fhPhNum
    <> S.word16 (fromIntegral $ S.size aSecHdr32)
    <> S.word16 fhShNum
    <> S.word16 (unSecIx fhSnStIx)

instance SizedSerializable FileHdr32 where
  size _ = 36
  {-# INLINE size #-}

instance Deserializable FileHdr32 where
  get = do
    fileType ← FileType <$> D.word16 <?> "file type"
    machine ← Machine <$> D.word16 <?> "machine"
    version ← D.word32 <?> "version"
    unless (version == 1) $ D.unexpected "Unexpected ELF version"
    entry ← D.word32 <?> "entry point address"
    phOff ← D.word32 <?> "program header table offset"
    shOff ← D.word32 <?> "section header table offset"
    flags ← MachFlags <$> D.word32 <?> "machine flags"
    fileHdrSize ← D.word16 <?> "file header size"
    unless (fileHdrSize ==
              fromIntegral (S.size anIdent + S.size aFileHdr32)) $
      D.unexpected "Unexpected ELF file header size"
    progHdrSize ← D.word16 <?> "program header size"
    unless (progHdrSize == fromIntegral (S.size aProgHdr32)) $
      D.unexpected "Unexpected ELF program header size"
    phNum ← D.word16 <?> "program header table size"
    secHdrSize ← D.word16 <?> "section header size"
    unless (secHdrSize == fromIntegral (S.size aSecHdr32)) $
      D.unexpected "Unexpected ELF section header size"
    shNum  ← D.word16 <?> "section header table size"
    snStIx ← SecIx <$> D.word16 <?> "section name string table section index"
    return $ FileHdr { fhType    = fileType
                     , fhMachine = machine
                     , fhEntry   = entry
                     , fhPhOff   = phOff
                     , fhShOff   = shOff
                     , fhFlags   = flags
                     , fhPhNum   = phNum
                     , fhShNum   = shNum
                     , fhSnStIx  = snStIx }

-- | ELF64 file header.
type FileHdr64 = FileHdr Elf64

-- | 'FileHdr64' proxy value.
aFileHdr64 ∷ Proxy FileHdr64
aFileHdr64 = Proxy

instance Serializable FileHdr64 where
  put (FileHdr {..})
    =  S.word16 (unFileType fhType)
    <> S.word16 (unMachine fhMachine)
    <> S.word32 1
    <> S.word64 fhEntry
    <> S.word64 fhPhOff
    <> S.word64 fhShOff
    <> S.word32 (unMachFlags fhFlags)
    <> S.word16 (fromIntegral $ S.size anIdent + S.size aFileHdr64)
    <> S.word16 (fromIntegral $ S.size aProgHdr64)
    <> S.word16 fhPhNum
    <> S.word16 (fromIntegral $ S.size aSecHdr64)
    <> S.word16 fhShNum
    <> S.word16 (unSecIx fhSnStIx)

instance SizedSerializable FileHdr64 where
  size _ = 56
  {-# INLINE size #-}

instance Deserializable FileHdr64 where
  get = do
    fileType ← FileType <$> D.word16 <?> "file type"
    machine ← Machine <$> D.word16 <?> "machine code"
    version ← D.word32 <?> "version"
    unless (version == 1) $ D.unexpected "Unexpected ELF version"
    entry ← D.word64 <?> "entry point address"
    phOff ← D.word64 <?> "program header table offset"
    shOff ← D.word64 <?> "section header table offset"
    flags ← MachFlags <$> D.word32 <?> "machine flags"
    fileHdrSize ← D.word16 <?> "file header size"
    unless (fileHdrSize ==
              fromIntegral (S.size anIdent + S.size aFileHdr64)) $
      D.unexpected "Unexpected ELF file header size"
    progHdrSize ← D.word16 <?> "program header size"
    unless (progHdrSize == fromIntegral (S.size aProgHdr64)) $
      D.unexpected "Unexpected ELF program header size"
    phNum ← D.word16 <?> "program header table size"
    secHdrSize ← D.word16 <?> "section header size"
    unless (secHdrSize == fromIntegral (S.size aSecHdr64)) $
      D.unexpected "Unexpected ELF section header size"
    shNum  ← D.word16 <?> "section header table size"
    snStIx ← SecIx <$> D.word16 <?> "section name string table section index"
    return $ FileHdr { fhType    = fileType
                     , fhMachine = machine
                     , fhEntry   = entry
                     , fhPhOff   = phOff
                     , fhShOff   = shOff
                     , fhFlags   = flags
                     , fhPhNum   = phNum
                     , fhShNum   = shNum
                     , fhSnStIx  = snStIx }

-- | Segment type.
newtype SegType = SegType { unSegType ∷ Word32 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Unused program header entry (@PT_NULL@).
unusedSegType ∷ SegType
unusedSegType = SegType 0

-- | Loadable segment (@PT_LOAD@).
loadSegType ∷ SegType
loadSegType = SegType 1

-- | Dynamic linking tables (@PT_DYNAMIC@).
dynSegType ∷ SegType
dynSegType = SegType 2

-- | Program interpreter path name (@PT_INTERP@).
interpSegType ∷ SegType
interpSegType = SegType 3

-- | Note sections (@PT_NOTE@).
noteSegType ∷ SegType
noteSegType = SegType 4

-- | A reserved segment type (@PT_SHLIB@).
shlibSegType ∷ SegType
shlibSegType = SegType 5

-- | Program header table (@PT_PHDR@).
phdrSegType ∷ SegType
phdrSegType = SegType 6

-- | First environment-specific segment type (@PT_LOOS@).
loOsSegType ∷ SegType
loOsSegType = SegType 0x60000000

-- | Last environment-specific segment type (@PT_HIOS@).
hiOsSegType ∷ SegType
hiOsSegType = SegType 0x6FFFFFFF

-- | First processor-specific segment type (@PT_LOPROC@).
loProcSegType ∷ SegType
loProcSegType = SegType 0x70000000

-- | Last processor-specific segment type (@PT_HIPROC@).
hiProcSegType ∷ SegType
hiProcSegType = SegType 0x7FFFFFFF

-- | Segment flags.
newtype SegFlags = SegFlags { unSegFlags ∷ Word32 }
                   deriving (Typeable, Data, Show, Read,
                             Eq, Flags, BoundedFlags)

-- | Execute permission (@PF_X@).
execSegFlag ∷ SegFlags
execSegFlag = SegFlags 1

-- | Write permission (@PF_W@).
writeSegFlag ∷ SegFlags
writeSegFlag = SegFlags 2

-- | Read permission (@PF_R@).
readSegFlag ∷ SegFlags
readSegFlag = SegFlags 4

-- | Environment-specific flags mask (@PF_MASKOS@).
osSegFlags ∷ SegFlags
osSegFlags = SegFlags 0x00FF0000

-- | Processor-specific flags mask (@PF_MASKPROC@).
procSegFlags ∷ SegFlags
procSegFlags = SegFlags 0xFF000000

-- | Program header table entry.
data ProgHdr c = ProgHdr { phType     ∷ SegType
                         , phFlags    ∷ SegFlags
                         , phOff      ∷ Off c
                         , phVirtAddr ∷ Addr c
                         , phPhysAddr ∷ Addr c
                         , phFileSize ∷ Off c
                         , phMemSize  ∷ Addr c
                         , phAlign    ∷ Addr c }
                 deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (ProgHdr c)
deriving instance IsFileClass c ⇒ Show (ProgHdr c)
deriving instance IsFileClass c ⇒ Read (ProgHdr c)
deriving instance IsFileClass c ⇒ Eq (ProgHdr c)

-- | ELF32 program header table entry.
type ProgHdr32 = ProgHdr Elf32

-- | 'ProgHdr32' proxy value.
aProgHdr32 ∷ Proxy ProgHdr32
aProgHdr32 = Proxy

instance Serializable ProgHdr32 where
  put (ProgHdr {..})
    =  S.word32 (unSegType phType)
    <> S.word32 phOff
    <> S.word32 phVirtAddr
    <> S.word32 phPhysAddr
    <> S.word32 phFileSize
    <> S.word32 phMemSize
    <> S.word32 (unSegFlags phFlags)
    <> S.word32 phAlign

instance SizedSerializable ProgHdr32 where
  size _ = 32
  {-# INLINE size #-}

instance Deserializable ProgHdr32 where
  get = do
    segType  ← SegType <$> D.word32 <?> "type"
    off      ← D.word32 <?> "offset"
    virtAddr ← D.word32 <?> "virtual address"
    physAddr ← D.word32 <?> "physical address"
    fileSize ← D.word32 <?> "in-file size"
    memSize  ← D.word32 <?> "in-memory size"
    flags    ← SegFlags <$> D.word32 <?> "flags"
    align    ← D.word32 <?> "alignment"
    return $ ProgHdr { phType = segType
                     , phOff  = off
                     , phVirtAddr = virtAddr
                     , phPhysAddr = physAddr
                     , phFileSize = fileSize
                     , phMemSize = memSize
                     , phFlags = flags
                     , phAlign = align }

-- | ELF64 program header table entry.
type ProgHdr64 = ProgHdr Elf64

-- | 'ProgHdr64' proxy value.
aProgHdr64 ∷ Proxy ProgHdr64
aProgHdr64 = Proxy

instance Serializable ProgHdr64 where
  put (ProgHdr {..})
    =  S.word32 (unSegType phType)
    <> S.word32 (unSegFlags phFlags)
    <> S.word64 phOff
    <> S.word64 phVirtAddr
    <> S.word64 phPhysAddr
    <> S.word64 phFileSize
    <> S.word64 phMemSize
    <> S.word64 phAlign

instance SizedSerializable ProgHdr64 where
  size _ = 56
  {-# INLINE size #-}

instance Deserializable ProgHdr64 where
  get = do
    segType  ← SegType <$> D.word32 <?> "type"
    flags    ← SegFlags <$> D.word32 <?> "flags"
    off      ← D.word64 <?> "offset"
    virtAddr ← D.word64 <?> "virtual address"
    physAddr ← D.word64 <?> "physical address"
    fileSize ← D.word64 <?> "in-file size"
    memSize  ← D.word64 <?> "in-memory size"
    align    ← D.word64 <?> "alignment"
    return $ ProgHdr { phType = segType
                     , phOff  = off
                     , phVirtAddr = virtAddr
                     , phPhysAddr = physAddr
                     , phFileSize = fileSize
                     , phMemSize = memSize
                     , phFlags = flags
                     , phAlign = align }

-- | String table index.
type StrIx = Word32

-- | Section header entry index.
newtype SecIx = SecIx { unSecIx ∷ Word16 }
                deriving (Typeable, Data, Show, Read,
                          Eq, Ord, Bounded, Enum, Ix, Num, Bits, FiniteBits,
                          Integral, Real)

-- | Undefined section reference (@SHN_UNDEF@).
undefSecIx ∷ SecIx
undefSecIx = 0

-- | Last regular section index.
lastSecIx ∷ SecIx
lastSecIx = 0xFEFF

-- | First environment-specific section index (@SHN_LOOS@).
loOsSecIx ∷ SecIx
loOsSecIx = 0xFF20

-- | Last environment-specific section index (@SHN_HIOS@).
hiOsSecIx ∷ SecIx
hiOsSecIx = 0xFF3F

-- | First processor-specific section index (@SHN_LOPROC@).
loProcSecIx ∷ SecIx
loProcSecIx = 0xFF00

-- | Last processor-specific section index (@SHN_HIPROC@).
hiProcSecIx ∷ SecIx
hiProcSecIx = 0xFF1F

-- | Absolute value indicator (@SHN_ABS@).
absSecIx ∷ SecIx
absSecIx = 0xFFF1

-- | Common block indicator (@SHN_COMMON@).
commonSecIx ∷ SecIx
commonSecIx = 0xFFF2

-- | Escape value (@SHN_XINDEX@).
xIndexSecIx ∷ SecIx
xIndexSecIx = 0xFFFF

-- | Section type.
newtype SecType = SecType { unSecType ∷ Word32 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Unused section (@SHT_NULL@).
unusedSecType ∷ SecType
unusedSecType = SecType 0

-- | Program information (@SHT_PROGBITS@).
progBitsSecType ∷ SecType
progBitsSecType = SecType 1

-- | Symbol table (@SHT_SYMTAB@).
symSecType ∷ SecType
symSecType = SecType 2

-- | String table (@SHT_STRTAB@).
strSecType ∷ SecType
strSecType = SecType 3

-- | Relocation entries (@SHT_RELA@).
relaSecType ∷ SecType
relaSecType = SecType 4

-- | Symbol hash table (@SHT_HASH@).
hashSecType ∷ SecType
hashSecType = SecType 5

-- | Dynamic linking table (@SHT_DYNAMIC@).
dynSecType ∷ SecType
dynSecType = SecType 6

-- | Note information (@SHT_NOTE@).
noteSecType ∷ SecType
noteSecType = SecType 7

-- | Uninitialized space (@SHT_NOBITS@).
noBitsSecType ∷ SecType
noBitsSecType = SecType 8

-- | Relocation entries (@SHT_REL@).
relSecType ∷ SecType
relSecType = SecType 9

-- | A reserved section type (@SHT_SHLIB@).
shlibSecType ∷ SecType
shlibSecType = SecType 10

-- | Dynamic loader symbol table (@SHT_DYNSYM@).
dynSymSecType ∷ SecType
dynSymSecType = SecType 11

-- | First environment-specific section type (@SHT_LOOS@).
loOsSecType ∷ SecType
loOsSecType = SecType 0x60000000

-- | Last environment-specific section type (@SHT_HIOS@).
hiOsSecType ∷ SecType
hiOsSecType = SecType 0x6FFFFFFF

-- | First processor-specific section type (@SHT_LOPROC@).
loProcSecType ∷ SecType
loProcSecType = SecType 0x70000000

-- | Last processor-specific section type (@SHT_HIPROC@).
hiProcSecType ∷ SecType
hiProcSecType = SecType 0x7FFFFFFF

-- | Section flags.
newtype SecFlags = SecFlags { unSecFlags ∷ Word32 }
                   deriving (Typeable, Data, Show, Read,
                             Eq, Flags, BoundedFlags)

-- | Writable data (@SHF_WRITE@).
writeSecFlag ∷ SecFlags
writeSecFlag = SecFlags 1

-- | Allocated data (@SHF_ALLOC@).
allocSecFlag ∷ SecFlags
allocSecFlag = SecFlags 2

-- | Executable instructions (@SHF_EXECINSTR@).
execSecFlag ∷ SecFlags
execSecFlag = SecFlags 4

-- | Mergeable data (@SHF_MERGE@).
mergeSecFlag ∷ SecFlags
mergeSecFlag = SecFlags 0x10

-- | Flag that indicates that 'shInfo' is a section header table index.
--   (@SHF_INFO_LINK@)
infoLinkSecFlag ∷ SecFlags
infoLinkSecFlag = SecFlags 0x40

-- | Environment-specific flags mask (@SHF_MASKOS@).
osSecFlags ∷ SecFlags
osSecFlags = SecFlags 0x0F000000

-- | Processor-specific flags mask (@SHF_MASKOS@).
procSecFlags ∷ SecFlags
procSecFlags = SecFlags 0xF0000000

-- | Section header table entry.
data SecHdr c = SecHdr { shName    ∷ StrIx
                       , shType    ∷ SecType
                       , shFlags   ∷ SecFlags
                       , shAddr    ∷ Addr c
                       , shOff     ∷ Off c
                       , shSize    ∷ Addr c
                       , shLink    ∷ Word32
                       , shInfo    ∷ Word32
                       , shAlign   ∷ Addr c
                       , shEntSize ∷ Addr c }
                deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (SecHdr c)
deriving instance IsFileClass c ⇒ Show (SecHdr c)
deriving instance IsFileClass c ⇒ Read (SecHdr c)
deriving instance IsFileClass c ⇒ Eq (SecHdr c)

-- | ELF32 section header table entry.
type SecHdr32 = SecHdr Elf32

-- | 'SecHdr32' proxy value.
aSecHdr32 ∷ Proxy SecHdr32
aSecHdr32 = Proxy

instance Serializable SecHdr32 where
  put (SecHdr {..})
    =  S.word32 shName
    <> S.word32 (unSecType shType)
    <> S.word32 (unSecFlags shFlags)
    <> S.word32 shAddr
    <> S.word32 shOff
    <> S.word32 shSize
    <> S.word32 shLink
    <> S.word32 shInfo
    <> S.word32 shAlign
    <> S.word32 shEntSize

instance SizedSerializable SecHdr32 where
  size _ = 40
  {-# INLINE size #-}

instance Deserializable SecHdr32 where
  get = do
    name    ← D.word32 <?> "name"
    tp      ← SecType <$> D.word32 <?> "type"
    flags   ← SecFlags <$> D.word32 <?> "flags"
    addr    ← D.word32 <?> "address"
    off     ← D.word32 <?> "offset"
    size    ← D.word32 <?> "size"
    link    ← D.word32 <?> "link"
    info    ← D.word32 <?> "extra information"
    align   ← D.word32 <?> "alignment"
    entSize ← D.word32 <?> "entry size"
    return $ SecHdr { shName    = name
                    , shType    = tp
                    , shFlags   = flags
                    , shAddr    = addr
                    , shOff     = off
                    , shSize    = size
                    , shLink    = link
                    , shInfo    = info
                    , shAlign   = align
                    , shEntSize = entSize }

-- | ELF64 section header table entry.
type SecHdr64 = SecHdr Elf64

-- | 'SecHdr64' proxy value.
aSecHdr64 ∷ Proxy SecHdr64
aSecHdr64 = Proxy

instance Serializable SecHdr64 where
  put (SecHdr {..})
    =  S.word32 shName
    <> S.word32 (unSecType shType)
    <> S.word64 (fromIntegral (unSecFlags shFlags))
    <> S.word64 shAddr
    <> S.word64 shOff
    <> S.word64 shSize
    <> S.word32 shLink
    <> S.word32 shInfo
    <> S.word64 shAlign
    <> S.word64 shEntSize

instance SizedSerializable SecHdr64 where
  size _ = 64
  {-# INLINE size #-}

instance Deserializable SecHdr64 where
  get = do
    name    ← D.word32 <?> "name"
    tp      ← SecType <$> D.word32 <?> "type"
    flags   ← SecFlags . fromIntegral <$> D.word64 <?> "flags"
    addr    ← D.word64 <?> "address"
    off     ← D.word64 <?> "offset"
    size    ← D.word64 <?> "size"
    link    ← D.word32 <?> "link"
    info    ← D.word32 <?> "extra information"
    align   ← D.word64 <?> "alignment"
    entSize ← D.word64 <?> "entry size"
    return $ SecHdr { shName    = name
                    , shType    = tp
                    , shFlags   = flags
                    , shAddr    = addr
                    , shOff     = off
                    , shSize    = size
                    , shLink    = link
                    , shInfo    = info
                    , shAlign   = align
                    , shEntSize = entSize }

-- | Section header filled with zeros.
zeroSecHdr ∷ IsFileClass c ⇒ SecHdr c
zeroSecHdr = SecHdr { shName    = 0
                    , shType    = unusedSecType
                    , shFlags   = noFlags
                    , shAddr    = 0
                    , shOff     = 0
                    , shSize    = 0
                    , shLink    = 0
                    , shInfo    = 0
                    , shAlign   = 0
                    , shEntSize = 0 }

-- | Symbol type.
newtype SymType = SymType { unSymType ∷ Word4 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Undefined symbol type (@STT_NOTYPE@).
undefSymType ∷ SymType
undefSymType = SymType 0

-- | Object (@STT_OBJECT@).
objSymType ∷ SymType
objSymType = SymType 1

-- | Function (@STT_FUNC@).
funSymType ∷ SymType
funSymType = SymType 2

-- | Section (@STT_SECTION@).
secSymType ∷ SymType
secSymType = SymType 3

-- | Source file name (@STT_FILE@).
fileSymType ∷ SymType
fileSymType = SymType 4

-- | Common block label (@STT_COMMON@).
commonSymType ∷ SymType
commonSymType = SymType 5

-- | Thread-local storage (@STT_TLS@).
tlsSymType ∷ SymType
tlsSymType = SymType 6

-- | First environment-specific symbol type (@STT_LOOS@).
loOsSymType ∷ SymType
loOsSymType = SymType 10

-- | Last environment-specific symbol type (@STT_HIOS@).
hiOsSymType ∷ SymType
hiOsSymType = SymType 12

-- | First processor-specific symbol type (@STT_LOPROC@).
loProcSymType ∷ SymType
loProcSymType = SymType 13

-- | Last processor-specific symbol type (@STT_HIPROC@).
hiProcSymType ∷ SymType
hiProcSymType = SymType 15

-- | Symbol binding type.
newtype SymBind = SymBind { unSymBind ∷ Word4 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Local symbol (@STB_LOCAL@).
localSymBind ∷ SymBind
localSymBind = SymBind 0

-- | Global symbol (@STB_GLOBAL@).
globalSymBind ∷ SymBind
globalSymBind = SymBind 1

-- | Lower precedence global symbol (@STB_WEAK@).
weakSymBind ∷ SymBind
weakSymBind = SymBind 2

-- | First environment-specific symbol binding type (@STB_LOOS@).
loOsSymBind ∷ SymBind
loOsSymBind = SymBind 10

-- | Last environment-specific symbol binding type (@STB_HIOS@).
hiOsSymBind ∷ SymBind
hiOsSymBind = SymBind 12

-- | First processor-specific symbol binding type (@STB_LOPROC@).
loProcSymBind ∷ SymBind
loProcSymBind = SymBind 13

-- | Last processor-specific symbol binding type (@STB_HIPROC@).
hiProcSymBind ∷ SymBind
hiProcSymBind = SymBind 15

-- | Symbol visibility.
newtype SymVisi = SymVisi { unSymVisi ∷ Word4 }
                  deriving (Typeable, Data, Show, Read,
                            Eq, Ord, Bounded, Enum, Ix)

-- | Default symbol visibility (specified by the binding type;
--   @STV_DEFAULT@).
defSymVisi ∷ SymVisi
defSymVisi = SymVisi 0

-- | Internal symbol visibility (processor-specific hidden type;
--   @STV_INTERNAL@).
intSymVisi ∷ SymVisi
intSymVisi = SymVisi 1

-- | Hidden symbol (@STV_HIDDEN@).
hiddenSymVisi ∷ SymVisi
hiddenSymVisi = SymVisi 2

-- | Protected symbol (@STV_PROTECTED@).
protSymVisi ∷ SymVisi
protSymVisi = SymVisi 3

-- | Global symbol (@STV_EXPORTED@).
exportSymVisi ∷ SymVisi
exportSymVisi = SymVisi 4

-- | Global singleton symbol (@STV_SINGLETON@).
singSymVisi ∷ SymVisi
singSymVisi = SymVisi 5

-- | Extra hidden symbol (@STV_ELIMINATE@).
elimSymVisi ∷ SymVisi
elimSymVisi = SymVisi 6

-- | Symbol table index.
newtype SymIx c = SymIx { unSymIx ∷ UnSymIx c }
                  deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (SymIx c)
deriving instance IsFileClass c ⇒ Show (SymIx c)
deriving instance IsFileClass c ⇒ Read (SymIx c)
deriving instance IsFileClass c ⇒ Eq (SymIx c)
deriving instance IsFileClass c ⇒ Ord (SymIx c)
deriving instance IsFileClass c ⇒ Bounded (SymIx c)
deriving instance IsFileClass c ⇒ Enum (SymIx c)
deriving instance IsFileClass c ⇒ Ix (SymIx c)
deriving instance IsFileClass c ⇒ Num (SymIx c)
deriving instance IsFileClass c ⇒ Bits (SymIx c)
deriving instance IsFileClass c ⇒ FiniteBits (SymIx c)
deriving instance IsFileClass c ⇒ Integral (SymIx c)
deriving instance IsFileClass c ⇒ Real (SymIx c)

-- | Undefined symbol table index.
undefSymIx ∷ IsFileClass c ⇒ SymIx c
undefSymIx = SymIx 0

-- | Symbol table entry.
data SymEnt c = SymEnt { symName  ∷ StrIx
                       , symBind  ∷ SymBind
                       , symType  ∷ SymType
                       , symVisi  ∷ SymVisi
                       , symSecIx ∷ SecIx
                       , symAddr  ∷ Addr c
                       , symSize  ∷ Addr c }
                deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (SymEnt c)
deriving instance IsFileClass c ⇒ Show (SymEnt c)
deriving instance IsFileClass c ⇒ Read (SymEnt c)
deriving instance IsFileClass c ⇒ Eq (SymEnt c)

-- | ELF32 symbol table entry.
type SymEnt32 = SymEnt Elf32

-- | 'SymEnt32' proxy value.
aSymEnt32 ∷ Proxy SymEnt32
aSymEnt32 = Proxy

instance Serializable SymEnt32 where
  put (SymEnt {..})
    =  S.word32 symName
    <> S.word32 symAddr
    <> S.word32 symSize
    <> S.word8 (shiftL (fromIntegral $ unSymBind symBind) 4 .|.
                fromIntegral (unSymType symType))
    <> S.word8 (fromIntegral (unSymVisi symVisi))
    <> S.word16 (unSecIx symSecIx)

instance SizedSerializable SymEnt32 where
  size _ = 16
  {-# INLINE size #-}

instance Deserializable SymEnt32 where
  get = do
    name  ← D.word32 <?> "name"
    addr  ← D.word32 <?> "address"
    size  ← D.word32 <?> "size"
    info  ← D.word8 <?> "info"
    let bind = SymBind (fromIntegral $ shiftR info 4)
        tp   = SymType (fromIntegral info)
    visi  ← SymVisi . fromIntegral <$> D.word8 <?> "visibility"
    secIx ← SecIx <$> D.word16 <?> "section index"
    return $ SymEnt { symName  = name
                    , symAddr  = addr
                    , symSize  = size
                    , symBind  = bind
                    , symType  = tp
                    , symVisi  = visi
                    , symSecIx = secIx }

-- | ELF64 symbol table entry.
type SymEnt64 = SymEnt Elf64

-- | 'SymEnt64' proxy value.
aSymEnt64 ∷ Proxy SymEnt64
aSymEnt64 = Proxy

instance Serializable SymEnt64 where
  put (SymEnt {..})
    =  S.word32 symName
    <> S.word8 (shiftL (fromIntegral $ unSymBind symBind) 4 .|.
                fromIntegral (unSymType symType))
    <> S.word8 (fromIntegral (unSymVisi symVisi))
    <> S.word16 (unSecIx symSecIx)
    <> S.word64 symAddr
    <> S.word64 symSize

instance SizedSerializable SymEnt64 where
  size _ = 24
  {-# INLINE size #-}

instance Deserializable SymEnt64 where
  get = do
    name  ← D.word32 <?> "name"
    info  ← D.word8 <?> "info"
    let bind = SymBind (fromIntegral $ shiftR info 4)
        tp   = SymType (fromIntegral info)
    visi  ← SymVisi . fromIntegral <$> D.word8 <?> "visibility"
    secIx ← SecIx <$> D.word16 <?> "section index"
    addr  ← D.word64 <?> "address"
    size  ← D.word64 <?> "size"
    return $ SymEnt { symName  = name
                    , symAddr  = addr
                    , symSize  = size
                    , symBind  = bind
                    , symType  = tp
                    , symVisi  = visi
                    , symSecIx = secIx }

-- | Symbol table entry filled with zeros.
zeroSymEnt ∷ IsFileClass c ⇒ SymEnt c
zeroSymEnt = SymEnt { symName  = 0
                    , symBind  = localSymBind
                    , symType  = undefSymType
                    , symVisi  = defSymVisi
                    , symSecIx = undefSecIx
                    , symAddr  = 0
                    , symSize  = 0 }

-- | Relocation type.
newtype RelType c = RelType { unRelType ∷ UnRelType c }
                    deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (RelType c)
deriving instance IsFileClass c ⇒ Show (RelType c)
deriving instance IsFileClass c ⇒ Read (RelType c)
deriving instance IsFileClass c ⇒ Eq (RelType c)
deriving instance IsFileClass c ⇒ Ord (RelType c)
deriving instance IsFileClass c ⇒ Bounded (RelType c)
deriving instance IsFileClass c ⇒ Enum (RelType c)
deriving instance IsFileClass c ⇒ Ix (RelType c)

-- | ELF32 relocation type.
type RelType32 = RelType Elf32

-- | ELF64 relocation type.
type RelType64 = RelType Elf64

-- | Relocation table entry (REL).
data RelEnt c = RelEnt { relOff   ∷ Addr c
                       , relSymIx ∷ SymIx c
                       , relType  ∷ RelType c }
                deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (RelEnt c)
deriving instance IsFileClass c ⇒ Show (RelEnt c)
deriving instance IsFileClass c ⇒ Read (RelEnt c)
deriving instance IsFileClass c ⇒ Eq (RelEnt c)

-- | ELF32 relocation table entry (REL).
type RelEnt32 = RelEnt Elf32

-- | 'RelEnt32' proxy value.
aRelEnt32 ∷ Proxy RelEnt32
aRelEnt32 = Proxy

instance Serializable RelEnt32 where
  put (RelEnt {..})
    =  S.word32 relOff
    <> S.word32 (shiftL (fromIntegral relSymIx) 8 .|.
                 fromIntegral (unRelType relType))

instance SizedSerializable RelEnt32 where
  size _ = 8
  {-# INLINE size #-}

instance Deserializable RelEnt32 where
  get = do
    off  ← D.word32 <?> "offset"
    info ← D.word32 <?> "info"
    let symIx = SymIx $ fromIntegral $ shiftR info 8
        tp    = RelType $ fromIntegral info
    return $ RelEnt { relOff   = off
                    , relSymIx = symIx
                    , relType  = tp }

-- | ELF64 relocation table entry (REL).
type RelEnt64 = RelEnt Elf64

-- | 'RelEnt64' proxy value.
aRelEnt64 ∷ Proxy RelEnt64
aRelEnt64 = Proxy

instance Serializable RelEnt64 where
  put (RelEnt {..})
    =  S.word64 relOff
    <> S.word64 (shiftL (fromIntegral relSymIx) 32 .|.
                 fromIntegral (unRelType relType))

instance SizedSerializable RelEnt64 where
  size _ = 16
  {-# INLINE size #-}

instance Deserializable RelEnt64 where
  get = do
    off  ← D.word64 <?> "offset"
    info ← D.word64 <?> "info"
    let symIx = SymIx $ fromIntegral $ shiftR info 32
        tp    = RelType $ fromIntegral info
    return $ RelEnt { relOff   = off
                    , relSymIx = symIx
                    , relType  = tp }

-- | Relocation table entry (RELA).
data RelaEnt c = RelaEnt { relaOff    ∷ Addr c
                         , relaSymIx  ∷ SymIx c
                         , relaType   ∷ RelType c
                         , relaAddend ∷ Addr c }
                 deriving Typeable

deriving instance (Data c, IsFileClass c) ⇒ Data (RelaEnt c)
deriving instance IsFileClass c ⇒ Show (RelaEnt c)
deriving instance IsFileClass c ⇒ Read (RelaEnt c)
deriving instance IsFileClass c ⇒ Eq (RelaEnt c)

-- | ELF32 relocation table entry (RELA).
type RelaEnt32 = RelaEnt Elf32

-- | 'RelaEnt32' proxy value.
aRelaEnt32 ∷ Proxy RelaEnt32
aRelaEnt32 = Proxy

instance Serializable RelaEnt32 where
  put (RelaEnt {..})
    =  S.word32 relaOff
    <> S.word32 (shiftL (fromIntegral relaSymIx) 8 .|.
                 fromIntegral (unRelType relaType))
    <> S.word32 relaAddend

instance SizedSerializable RelaEnt32 where
  size _ = 12
  {-# INLINE size #-}

instance Deserializable RelaEnt32 where
  get = do
    off    ← D.word32 <?> "offset"
    info   ← D.word32 <?> "info"
    let symIx = SymIx $ fromIntegral $ shiftR info 8
        tp    = RelType $ fromIntegral info
    addend ← D.word32 <?> "addend"
    return $ RelaEnt { relaOff    = off
                     , relaSymIx  = symIx
                     , relaType   = tp
                     , relaAddend = addend }

-- | ELF64 relocation table entry (RELA).
type RelaEnt64 = RelaEnt Elf64

-- | 'RelaEnt64' proxy value.
aRelaEnt64 ∷ Proxy RelaEnt64
aRelaEnt64 = Proxy

instance Serializable RelaEnt64 where
  put (RelaEnt {..})
    =  S.word64 relaOff
    <> S.word64 (shiftL (fromIntegral relaSymIx) 32 .|.
                 fromIntegral (unRelType relaType))
    <> S.word64 relaAddend

instance SizedSerializable RelaEnt64 where
  size _ = 24
  {-# INLINE size #-}

instance Deserializable RelaEnt64 where
  get = do
    off    ← D.word64 <?> "offset"
    info   ← D.word64 <?> "info"
    let symIx = SymIx $ fromIntegral $ shiftR info 32
        tp    = RelType $ fromIntegral info
    addend ← D.word64 <?> "addend"
    return $ RelaEnt { relaOff    = off
                     , relaSymIx  = symIx
                     , relaType   = tp
                     , relaAddend = addend }
