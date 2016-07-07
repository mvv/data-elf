{-# LANGUAGE UnicodeSyntax #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeFamilies #-}

-- | This module provides ELF data structures and (de)serialization routines.
module Data.Elf
  ( FileClass(..)
  , invalidFileClass
  , elf32FileClass
  , elf64FileClass
  , IsFileClass(..)
  , Elf32(..)
  , anElf32
  , Elf64(..)
  , anElf64
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
  , Machine(..)
  , undefMachine
  , i386Machine
  , amd64Machine
  , MachFlags(..)
  , Version(..)
  , invalidVersion
  , firstVersion
  , DataEnc(..)
  , invalidDataEnc
  , lsbDataEnc
  , msbDataEnc
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
  , Ident(..)
  , identSize
  , buildIdent
  , FileHdr(..)
  , FileHdr32
  , FileHdr64
  , fileHdr32Size
  , fileHdr64Size
  , putFileHdr32
  , getFileHdr32
  , buildFileHdr32
  , buildFileHdr64
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
  , SegFlags(..)
  , execSegFlag
  , writeSegFlag
  , readSegFlag
  , osSegFlags
  , procSegFlags
  , ProgHdr(..)
  , ProgHdr32
  , ProgHdr64
  , progHdr32Size
  , progHdr64Size
  , putProgHdr32
  , getProgHdr32
  , buildProgHdr32
  , buildProgHdr64
  , StrIx
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
  , SecFlags(..)
  , writeSecFlag
  , allocSecFlag
  , execSecFlag
  , mergeSecFlag
  , infoLinkSecFlag
  , osSecFlags
  , procSecFlags
  , SecHdr(..)
  , SecHdr32
  , SecHdr64
  , secHdr32Size
  , secHdr64Size
  , buildSecHdr32
  , buildSecHdr64
  , zeroSecHdr
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
  , SymBind(..)
  , localSymBind
  , globalSymBind
  , weakSymBind
  , loOsSymBind
  , hiOsSymBind
  , loProcSymBind
  , hiProcSymBind
  , SymVisi(..)
  , unSymVisi
  , SymIx(..)
  , undefSymIx
  , SymEnt(..)
  , SymEnt32
  , SymEnt64
  , symEnt32Size
  , symEnt64Size
  , buildSymEnt32
  , buildSymEnt64
  , zeroSymEnt
  , RelType(..)
  , RelType32
  , RelType64
  , RelEnt(..)
  , RelEnt32
  , RelEnt64
  , RelaEnt(..)
  , RelaEnt32
  , RelaEnt64
  , relaEnt32Size
  , relaEnt64Size
  , buildRelaEnt32
  , buildRelaEnt64
  ) where

import Data.Typeable (Typeable)
import Data.Data (Data)
import Data.Proxy (Proxy(..))
import Data.Ix (Ix)
import Data.Endian
import Data.Bits (Bits, shiftL, (.|.), FiniteBits)
import Data.Flags (Flags(noFlags), BoundedFlags)
import Data.Word (Word8, Word16, Word32, Word64)
import Data.ShortWord (Word2, Word4, Word24)
import Data.Monoid ((<>))
import qualified Data.ByteString.Builder as BB
import Data.Binary (Binary)
import qualified Data.Binary as Bin
import qualified Data.Binary.Put as Bin
import qualified Data.Binary.Get as Bin
import Text.Ascii (ascii)
import Control.Applicative ((<$>))
import Control.Monad (unless)

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
msbDataEnc = DataEnc 1

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
             deriving (Typeable, Data)

-- | Identification serialized size.
identSize ∷ Int
identSize = 16
{-# INLINE identSize #-}

instance Binary Ident where
  put (Ident {..}) = do
    Bin.putWord8 0x7F
    Bin.putWord8 (ascii 'E')
    Bin.putWord8 (ascii 'L')
    Bin.putWord8 (ascii 'F')
    Bin.putWord8 (unFileClass idClass)
    Bin.putWord8 (unDataEnc idDataEnc)
    Bin.putWord8 (unVersion idVersion)
    Bin.putWord8 (unOsAbi idOsAbi)
    Bin.putWord8 (unAbiVer idAbiVer)
    Bin.putWord8 0
    Bin.putWord8 0
    Bin.putWord8 0
    Bin.putWord8 0
    Bin.putWord8 0
    Bin.putWord8 0
    Bin.putWord8 0
  get = do
    b₀ ← Bin.getWord8
    unless (b₀ == 0x7F) $ fail "Invalid ELF magic number"
    b₁ ← Bin.getWord8
    unless (b₁ == ascii 'E') $ fail "Invalid ELF magic number"
    b₂ ← Bin.getWord8
    unless (b₂ == ascii 'L') $ fail "Invalid ELF magic number"
    b₃ ← Bin.getWord8
    unless (b₃ == ascii 'F') $ fail "Invalid ELF magic number"
    fileCls ← FileClass <$> Bin.getWord8
    dataEnc ← DataEnc <$> Bin.getWord8
    version ← Version <$> Bin.getWord8
    osAbi   ← OsAbi <$> Bin.getWord8
    abiVer  ← AbiVer <$> Bin.getWord8
    Bin.skip 7
    return $ Ident { idClass   = fileCls
                   , idDataEnc = dataEnc
                   , idVersion = version
                   , idOsAbi   = osAbi
                   , idAbiVer  = abiVer }

-- | Serialize identification via 'ByteString' builder.
buildIdent ∷ Ident → BB.Builder
buildIdent (Ident {..}) =  BB.word8 0x7F
                        <> BB.word8 (ascii 'E')
                        <> BB.word8 (ascii 'L')
                        <> BB.word8 (ascii 'F')
                        <> BB.word8 (unFileClass idClass)
                        <> BB.word8 (unDataEnc idDataEnc)
                        <> BB.word8 (unVersion idVersion)
                        <> BB.word8 (unOsAbi idOsAbi)
                        <> BB.word8 (unAbiVer idAbiVer)
                        <> BB.word8 0
                        <> BB.word8 0
                        <> BB.word8 0
                        <> BB.word8 0
                        <> BB.word8 0
                        <> BB.word8 0
                        <> BB.word8 0

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

-- | ELF32 file header.
type FileHdr32 = FileHdr Elf32

-- | ELF64 file header.
type FileHdr64 = FileHdr Elf64

-- | ELF32 file header size.
fileHdr32Size ∷ Int
fileHdr32Size = 36

-- | ELF64 file header size.
fileHdr64Size ∷ Int
fileHdr64Size = 56

-- | Serialize ELF32 file header via 'Bin.PutM' monad.
putFileHdr32 ∷ Endian → FileHdr32 → Bin.Put
putFileHdr32 endian (FileHdr {..}) = do
    word16 (unFileType fhType)
    word16 (unMachine fhMachine)
    word32 1
    word32 fhEntry
    word32 fhPhOff
    word32 fhShOff
    word32 (unMachFlags fhFlags)
    word16 (fromIntegral $ identSize + fileHdr32Size)
    word16 (fromIntegral progHdr32Size)
    word16 fhPhNum
    word16 (fromIntegral secHdr32Size)
    word16 fhShNum
    word16 (unSecIx fhSnStIx)
  where word16 | isLittleEndian endian = Bin.putWord16le
               | otherwise             = Bin.putWord16be
        word32 | isLittleEndian endian = Bin.putWord32le
               | otherwise             = Bin.putWord32be

-- | Deserialize ELF32 file header via 'Bin.Get' monad.
getFileHdr32 ∷ Endian → Bin.Get FileHdr32
getFileHdr32 endian = do
    fileType ← FileType <$> word16
    machine ← Machine <$> word16
    version ← word32
    unless (version == 1) $ fail "Unexpected ELF version"
    entry ← word32
    phOff ← word32
    shOff ← word32
    flags ← MachFlags <$> word32
    fileHdrSize ← word16
    unless (fileHdrSize == fromIntegral (identSize + fileHdr32Size)) $
      fail "Unexpected ELF file header size"
    progHdrSize ← word16
    unless (progHdrSize == fromIntegral progHdr32Size) $
      fail "Unexpected ELF program header size"
    phNum ← word16
    secHdrSize ← word16
    unless (secHdrSize == fromIntegral secHdr32Size) $
      fail "Unexpected ELF section header size"
    shNum  ← word16
    snStIx ← SecIx <$> word16
    return $ FileHdr { fhType    = fileType
                     , fhMachine = machine
                     , fhEntry   = entry
                     , fhPhOff   = phOff
                     , fhShOff   = shOff
                     , fhFlags   = flags
                     , fhPhNum   = phNum
                     , fhShNum   = shNum
                     , fhSnStIx  = snStIx }
  where word16 | isLittleEndian endian = Bin.getWord16le
               | otherwise             = Bin.getWord16be
        word32 | isLittleEndian endian = Bin.getWord32le
               | otherwise             = Bin.getWord32be

-- | Serialize ELF32 file header via 'ByteString' builder.
buildFileHdr32 ∷ Endian → FileHdr32 → BB.Builder
buildFileHdr32 endian (FileHdr {..})
  =  word16 (unFileType fhType)
  <> word16 (unMachine fhMachine)
  <> word32 1
  <> word32 fhEntry
  <> word32 fhPhOff
  <> word32 fhShOff
  <> word32 (unMachFlags fhFlags)
  <> word16 (fromIntegral $ identSize + fileHdr32Size)
  <> word16 (fromIntegral progHdr32Size)
  <> word16 fhPhNum
  <> word16 (fromIntegral secHdr32Size)
  <> word16 fhShNum
  <> word16 (unSecIx fhSnStIx)
  where word16 = if isLittleEndian endian then BB.word16LE else BB.word16BE
        word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE

-- | Serialize ELF64 file header via 'ByteString' builder.
buildFileHdr64 ∷ Endian → FileHdr64 → BB.Builder
buildFileHdr64 endian (FileHdr {..})
  =  word16 (unFileType fhType)
  <> word16 (unMachine fhMachine)
  <> word32 1
  <> word64 fhEntry
  <> word64 fhPhOff
  <> word64 fhShOff
  <> word32 (unMachFlags fhFlags)
  <> word16 (fromIntegral $ identSize + fileHdr64Size)
  <> word16 (fromIntegral progHdr64Size)
  <> word16 fhPhNum
  <> word16 (fromIntegral secHdr64Size)
  <> word16 fhShNum
  <> word16 (unSecIx fhSnStIx)
  where word16 = if isLittleEndian endian then BB.word16LE else BB.word16BE
        word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE
        word64 = if isLittleEndian endian then BB.word64LE else BB.word64BE

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

-- | ELF32 program header table entry.
type ProgHdr32 = ProgHdr Elf32

-- | ELF64 program header table entry.
type ProgHdr64 = ProgHdr Elf64

-- | ELF32 program header table entry size.
progHdr32Size ∷ Int
progHdr32Size = 32

-- | ELF64 program header table entry size.
progHdr64Size ∷ Int
progHdr64Size = 56

-- | Serialize ELF32 program header via 'Bin.PutM' monad.
putProgHdr32 ∷ Endian → ProgHdr32 → Bin.Put
putProgHdr32 endian (ProgHdr {..}) = do
    word32 (unSegType phType)
    word32 phOff
    word32 phVirtAddr
    word32 phPhysAddr
    word32 phFileSize
    word32 phMemSize
    word32 (unSegFlags phFlags)
    word32 phAlign
  where word32 | isLittleEndian endian = Bin.putWord32le
               | otherwise             = Bin.putWord32be

-- | Deserialize ELF32 program header via 'Bin.Get' monad.
getProgHdr32 ∷ Endian → Bin.Get ProgHdr32
getProgHdr32 endian = do
    segType ← SegType <$> word32
    off ← word32
    virtAddr ← word32
    physAddr ← word32
    fileSize ← word32
    memSize ← word32
    flags ← SegFlags <$> word32
    align ← word32
    return $ ProgHdr { phType = segType
                     , phOff  = off
                     , phVirtAddr = virtAddr
                     , phPhysAddr = physAddr
                     , phFileSize = fileSize
                     , phMemSize = memSize
                     , phFlags = flags
                     , phAlign = align }
  where word32 | isLittleEndian endian = Bin.getWord32le
               | otherwise             = Bin.getWord32be

-- | Serialize ELF32 program header via 'ByteString' builder.
buildProgHdr32 ∷ Endian → ProgHdr32 → BB.Builder
buildProgHdr32 endian (ProgHdr {..})
  =  word32 (unSegType phType)
  <> word32 phOff
  <> word32 phVirtAddr
  <> word32 phPhysAddr
  <> word32 phFileSize
  <> word32 phMemSize
  <> word32 (unSegFlags phFlags)
  <> word32 phAlign
  where word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE

-- | Serialize ELF64 program header via 'ByteString' builder.
buildProgHdr64 ∷ Endian → ProgHdr64 → BB.Builder
buildProgHdr64 endian (ProgHdr {..})
  =  word32 (unSegType phType)
  <> word32 (unSegFlags phFlags)
  <> word64 phOff
  <> word64 phVirtAddr
  <> word64 phPhysAddr
  <> word64 phFileSize
  <> word64 phMemSize
  <> word64 phAlign
  where word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE
        word64 = if isLittleEndian endian then BB.word64LE else BB.word64BE

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

-- | ELF32 section header table entry.
type SecHdr32 = SecHdr Elf32

-- | ELF64 section header table entry.
type SecHdr64 = SecHdr Elf64

-- | ELF32 section header table entry size.
secHdr32Size ∷ Int
secHdr32Size = 40

-- | ELF64 section header table entry size.
secHdr64Size ∷ Int
secHdr64Size = 64

-- | Serialize ELF32 section header via 'ByteString' builder.
buildSecHdr32 ∷ Endian → SecHdr32 → BB.Builder
buildSecHdr32 endian (SecHdr {..})
  =  word32 shName
  <> word32 (unSecType shType)
  <> word32 (unSecFlags shFlags)
  <> word32 shAddr
  <> word32 shOff
  <> word32 shSize
  <> word32 shLink
  <> word32 shInfo
  <> word32 shAlign
  <> word32 shEntSize
  where word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE

-- | Serialize ELF64 section header via 'ByteString' builder.
buildSecHdr64 ∷ Endian → SecHdr64 → BB.Builder
buildSecHdr64 endian (SecHdr {..})
  =  word32 shName
  <> word32 (unSecType shType)
  <> word64 (fromIntegral (unSecFlags shFlags))
  <> word64 shAddr
  <> word64 shOff
  <> word64 shSize
  <> word32 shLink
  <> word32 shInfo
  <> word64 shAlign
  <> word64 shEntSize
  where word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE
        word64 = if isLittleEndian endian then BB.word64LE else BB.word64BE

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
data SymVisi = DefSymVisi    -- ^ Default (specified by the binding type)
                             --   (@STV_DEFAULT@)
             | IntSymVisi    -- ^ Internal (processor-specific hidden type)
                             --   (@STV_INTERNAL@)
             | HiddenSymVisi -- ^ Hidden (@STV_HIDDEN@)
             | ProtSymVisi   -- ^ Protected (@STV_PROTECTED@)
             deriving (Typeable, Data, Show, Read,
                       Eq, Ord, Bounded, Enum, Ix)

-- | Symbol visibility code.
unSymVisi ∷ SymVisi → Word2
unSymVisi DefSymVisi = 0
unSymVisi IntSymVisi = 1
unSymVisi HiddenSymVisi = 2
unSymVisi ProtSymVisi = 3

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

-- | ELF32 symbol table entry.
type SymEnt32 = SymEnt Elf32

-- | ELF64 symbol table entry.
type SymEnt64 = SymEnt Elf64

-- | ELF32 symbol table entry size.
symEnt32Size ∷ Int
symEnt32Size = 16

-- | ELF64 symbol table entry size.
symEnt64Size ∷ Int
symEnt64Size = 24

-- | Serialize ELF32 symbol table entry via 'ByteString' builder.
buildSymEnt32 ∷ Endian → SymEnt32 → BB.Builder
buildSymEnt32 endian (SymEnt {..})
  =  word32 symName
  <> word32 symAddr
  <> word32 symSize
  <> BB.word8 (shiftL (fromIntegral $ unSymBind symBind) 4 .|.
               fromIntegral (unSymType symType))
  <> BB.word8 (fromIntegral (unSymVisi symVisi))
  <> word16 (unSecIx symSecIx)
  where word16 = if isLittleEndian endian then BB.word16LE else BB.word16BE
        word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE

-- | Serialize ELF64 symbol table entry via 'ByteString' builder.
buildSymEnt64 ∷ Endian → SymEnt64 → BB.Builder
buildSymEnt64 endian (SymEnt {..})
  =  word32 symName
  <> BB.word8 (shiftL (fromIntegral $ unSymBind symBind) 4 .|.
               fromIntegral (unSymType symType))
  <> BB.word8 (fromIntegral $ unSymVisi symVisi)
  <> word16 (unSecIx symSecIx)
  <> word64 symAddr
  <> word64 symSize
  where word16 = if isLittleEndian endian then BB.word16LE else BB.word16BE
        word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE
        word64 = if isLittleEndian endian then BB.word64LE else BB.word64BE

-- | Symbol table entry filled with zeros.
zeroSymEnt ∷ IsFileClass c ⇒ SymEnt c
zeroSymEnt = SymEnt { symName  = 0
                    , symBind  = localSymBind
                    , symType  = undefSymType
                    , symVisi  = DefSymVisi
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

-- | ELF64 relocation table entry (REL).
type RelEnt64 = RelEnt Elf64

-- | Relocation table entry (RELA).
data RelaEnt c = RelaEnt { relaOff    ∷ Addr c
                         , relaSymIx  ∷ SymIx c
                         , relaType   ∷ RelType c
                         , relaAddend ∷ Addr c }
                 deriving Typeable

-- | ELF32 relocation table entry (RELA).
type RelaEnt32 = RelaEnt Elf32

-- | ELF64 relocation table entry (RELA).
type RelaEnt64 = RelaEnt Elf64

deriving instance (Data c, IsFileClass c) ⇒ Data (RelaEnt c)
deriving instance IsFileClass c ⇒ Show (RelaEnt c)
deriving instance IsFileClass c ⇒ Read (RelaEnt c)
deriving instance IsFileClass c ⇒ Eq (RelaEnt c)

-- | ELF32 relocation table entry (RELA) size.
relaEnt32Size ∷ Int
relaEnt32Size = 12

-- | ELF64 relocation table entry (RELA) size.
relaEnt64Size ∷ Int
relaEnt64Size = 24

-- | Serialize ELF32 relocation table entry (RELA) via 'ByteString'
--   builder.
buildRelaEnt32 ∷ Endian → RelaEnt32 → BB.Builder
buildRelaEnt32 endian (RelaEnt {..})
  =  word32 relaOff
  <> word32 (shiftL (fromIntegral relaSymIx) 8 .|.
             fromIntegral (unRelType relaType))
  <> word32 relaAddend
  where word32 = if isLittleEndian endian then BB.word32LE else BB.word32BE

-- | Serialize ELF64 relocation table entry (RELA) via 'ByteString'
--   builder.
buildRelaEnt64 ∷ Endian → RelaEnt64 → BB.Builder
buildRelaEnt64 endian (RelaEnt {..})
  =  word64 relaOff
  <> word64 (shiftL (fromIntegral relaSymIx) 32 .|.
             fromIntegral (unRelType relaType))
  <> word64 relaAddend
  where word64 = if isLittleEndian endian then BB.word64LE else BB.word64BE
