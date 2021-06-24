// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: vss.proto

#ifndef PROTOBUF_INCLUDED_vss_2eproto
#define PROTOBUF_INCLUDED_vss_2eproto

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 3006001
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 3006001 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)
#define PROTOBUF_INTERNAL_EXPORT_protobuf_vss_2eproto 

namespace protobuf_vss_2eproto {
// Internal implementation detail -- do not use these members.
struct TableStruct {
  static const ::google::protobuf::internal::ParseTableField entries[];
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[];
  static const ::google::protobuf::internal::ParseTable schema[1];
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
void AddDescriptors();
}  // namespace protobuf_vss_2eproto
namespace tenon {
namespace vss {
namespace protobuf {
class VssMessage;
class VssMessageDefaultTypeInternal;
extern VssMessageDefaultTypeInternal _VssMessage_default_instance_;
}  // namespace protobuf
}  // namespace vss
}  // namespace tenon
namespace google {
namespace protobuf {
template<> ::tenon::vss::protobuf::VssMessage* Arena::CreateMaybeMessage<::tenon::vss::protobuf::VssMessage>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace tenon {
namespace vss {
namespace protobuf {

// ===================================================================

class VssMessage : public ::google::protobuf::Message /* @@protoc_insertion_point(class_definition:tenon.vss.protobuf.VssMessage) */ {
 public:
  VssMessage();
  virtual ~VssMessage();

  VssMessage(const VssMessage& from);

  inline VssMessage& operator=(const VssMessage& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  VssMessage(VssMessage&& from) noexcept
    : VssMessage() {
    *this = ::std::move(from);
  }

  inline VssMessage& operator=(VssMessage&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _internal_metadata_.unknown_fields();
  }
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return _internal_metadata_.mutable_unknown_fields();
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const VssMessage& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const VssMessage* internal_default_instance() {
    return reinterpret_cast<const VssMessage*>(
               &_VssMessage_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  void Swap(VssMessage* other);
  friend void swap(VssMessage& a, VssMessage& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline VssMessage* New() const final {
    return CreateMaybeMessage<VssMessage>(NULL);
  }

  VssMessage* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<VssMessage>(arena);
  }
  void CopyFrom(const ::google::protobuf::Message& from) final;
  void MergeFrom(const ::google::protobuf::Message& from) final;
  void CopyFrom(const VssMessage& from);
  void MergeFrom(const VssMessage& from);
  void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  ::google::protobuf::uint8* InternalSerializeWithCachedSizesToArray(
      bool deterministic, ::google::protobuf::uint8* target) const final;
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const final;
  void InternalSwap(VssMessage* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return NULL;
  }
  inline void* MaybeArenaPtr() const {
    return NULL;
  }
  public:

  ::google::protobuf::Metadata GetMetadata() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // optional bytes pubkey = 6;
  bool has_pubkey() const;
  void clear_pubkey();
  static const int kPubkeyFieldNumber = 6;
  const ::std::string& pubkey() const;
  void set_pubkey(const ::std::string& value);
  #if LANG_CXX11
  void set_pubkey(::std::string&& value);
  #endif
  void set_pubkey(const char* value);
  void set_pubkey(const void* value, size_t size);
  ::std::string* mutable_pubkey();
  ::std::string* release_pubkey();
  void set_allocated_pubkey(::std::string* pubkey);

  // optional bytes sign_ch = 7;
  bool has_sign_ch() const;
  void clear_sign_ch();
  static const int kSignChFieldNumber = 7;
  const ::std::string& sign_ch() const;
  void set_sign_ch(const ::std::string& value);
  #if LANG_CXX11
  void set_sign_ch(::std::string&& value);
  #endif
  void set_sign_ch(const char* value);
  void set_sign_ch(const void* value, size_t size);
  ::std::string* mutable_sign_ch();
  ::std::string* release_sign_ch();
  void set_allocated_sign_ch(::std::string* sign_ch);

  // optional bytes sign_res = 8;
  bool has_sign_res() const;
  void clear_sign_res();
  static const int kSignResFieldNumber = 8;
  const ::std::string& sign_res() const;
  void set_sign_res(const ::std::string& value);
  #if LANG_CXX11
  void set_sign_res(::std::string&& value);
  #endif
  void set_sign_res(const char* value);
  void set_sign_res(const void* value, size_t size);
  ::std::string* mutable_sign_res();
  ::std::string* release_sign_res();
  void set_allocated_sign_res(::std::string* sign_res);

  // optional uint64 random_hash = 1;
  bool has_random_hash() const;
  void clear_random_hash();
  static const int kRandomHashFieldNumber = 1;
  ::google::protobuf::uint64 random_hash() const;
  void set_random_hash(::google::protobuf::uint64 value);

  // optional uint64 random = 2;
  bool has_random() const;
  void clear_random();
  static const int kRandomFieldNumber = 2;
  ::google::protobuf::uint64 random() const;
  void set_random(::google::protobuf::uint64 value);

  // optional uint64 split_index = 4;
  bool has_split_index() const;
  void clear_split_index();
  static const int kSplitIndexFieldNumber = 4;
  ::google::protobuf::uint64 split_index() const;
  void set_split_index(::google::protobuf::uint64 value);

  // optional uint64 split_random = 5;
  bool has_split_random() const;
  void clear_split_random();
  static const int kSplitRandomFieldNumber = 5;
  ::google::protobuf::uint64 split_random() const;
  void set_split_random(::google::protobuf::uint64 value);

  // optional uint64 tm_height = 9;
  bool has_tm_height() const;
  void clear_tm_height();
  static const int kTmHeightFieldNumber = 9;
  ::google::protobuf::uint64 tm_height() const;
  void set_tm_height(::google::protobuf::uint64 value);

  // optional uint64 elect_height = 10;
  bool has_elect_height() const;
  void clear_elect_height();
  static const int kElectHeightFieldNumber = 10;
  ::google::protobuf::uint64 elect_height() const;
  void set_elect_height(::google::protobuf::uint64 value);

  // @@protoc_insertion_point(class_scope:tenon.vss.protobuf.VssMessage)
 private:
  void set_has_random_hash();
  void clear_has_random_hash();
  void set_has_random();
  void clear_has_random();
  void set_has_split_index();
  void clear_has_split_index();
  void set_has_split_random();
  void clear_has_split_random();
  void set_has_pubkey();
  void clear_has_pubkey();
  void set_has_sign_ch();
  void clear_has_sign_ch();
  void set_has_sign_res();
  void clear_has_sign_res();
  void set_has_tm_height();
  void clear_has_tm_height();
  void set_has_elect_height();
  void clear_has_elect_height();

  ::google::protobuf::internal::InternalMetadataWithArena _internal_metadata_;
  ::google::protobuf::internal::HasBits<1> _has_bits_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  ::google::protobuf::internal::ArenaStringPtr pubkey_;
  ::google::protobuf::internal::ArenaStringPtr sign_ch_;
  ::google::protobuf::internal::ArenaStringPtr sign_res_;
  ::google::protobuf::uint64 random_hash_;
  ::google::protobuf::uint64 random_;
  ::google::protobuf::uint64 split_index_;
  ::google::protobuf::uint64 split_random_;
  ::google::protobuf::uint64 tm_height_;
  ::google::protobuf::uint64 elect_height_;
  friend struct ::protobuf_vss_2eproto::TableStruct;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// VssMessage

// optional uint64 random_hash = 1;
inline bool VssMessage::has_random_hash() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void VssMessage::set_has_random_hash() {
  _has_bits_[0] |= 0x00000008u;
}
inline void VssMessage::clear_has_random_hash() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void VssMessage::clear_random_hash() {
  random_hash_ = GOOGLE_ULONGLONG(0);
  clear_has_random_hash();
}
inline ::google::protobuf::uint64 VssMessage::random_hash() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.random_hash)
  return random_hash_;
}
inline void VssMessage::set_random_hash(::google::protobuf::uint64 value) {
  set_has_random_hash();
  random_hash_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.random_hash)
}

// optional uint64 random = 2;
inline bool VssMessage::has_random() const {
  return (_has_bits_[0] & 0x00000010u) != 0;
}
inline void VssMessage::set_has_random() {
  _has_bits_[0] |= 0x00000010u;
}
inline void VssMessage::clear_has_random() {
  _has_bits_[0] &= ~0x00000010u;
}
inline void VssMessage::clear_random() {
  random_ = GOOGLE_ULONGLONG(0);
  clear_has_random();
}
inline ::google::protobuf::uint64 VssMessage::random() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.random)
  return random_;
}
inline void VssMessage::set_random(::google::protobuf::uint64 value) {
  set_has_random();
  random_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.random)
}

// optional uint64 split_index = 4;
inline bool VssMessage::has_split_index() const {
  return (_has_bits_[0] & 0x00000020u) != 0;
}
inline void VssMessage::set_has_split_index() {
  _has_bits_[0] |= 0x00000020u;
}
inline void VssMessage::clear_has_split_index() {
  _has_bits_[0] &= ~0x00000020u;
}
inline void VssMessage::clear_split_index() {
  split_index_ = GOOGLE_ULONGLONG(0);
  clear_has_split_index();
}
inline ::google::protobuf::uint64 VssMessage::split_index() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.split_index)
  return split_index_;
}
inline void VssMessage::set_split_index(::google::protobuf::uint64 value) {
  set_has_split_index();
  split_index_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.split_index)
}

// optional uint64 split_random = 5;
inline bool VssMessage::has_split_random() const {
  return (_has_bits_[0] & 0x00000040u) != 0;
}
inline void VssMessage::set_has_split_random() {
  _has_bits_[0] |= 0x00000040u;
}
inline void VssMessage::clear_has_split_random() {
  _has_bits_[0] &= ~0x00000040u;
}
inline void VssMessage::clear_split_random() {
  split_random_ = GOOGLE_ULONGLONG(0);
  clear_has_split_random();
}
inline ::google::protobuf::uint64 VssMessage::split_random() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.split_random)
  return split_random_;
}
inline void VssMessage::set_split_random(::google::protobuf::uint64 value) {
  set_has_split_random();
  split_random_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.split_random)
}

// optional bytes pubkey = 6;
inline bool VssMessage::has_pubkey() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void VssMessage::set_has_pubkey() {
  _has_bits_[0] |= 0x00000001u;
}
inline void VssMessage::clear_has_pubkey() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void VssMessage::clear_pubkey() {
  pubkey_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_pubkey();
}
inline const ::std::string& VssMessage::pubkey() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.pubkey)
  return pubkey_.GetNoArena();
}
inline void VssMessage::set_pubkey(const ::std::string& value) {
  set_has_pubkey();
  pubkey_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.pubkey)
}
#if LANG_CXX11
inline void VssMessage::set_pubkey(::std::string&& value) {
  set_has_pubkey();
  pubkey_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:tenon.vss.protobuf.VssMessage.pubkey)
}
#endif
inline void VssMessage::set_pubkey(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  set_has_pubkey();
  pubkey_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:tenon.vss.protobuf.VssMessage.pubkey)
}
inline void VssMessage::set_pubkey(const void* value, size_t size) {
  set_has_pubkey();
  pubkey_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:tenon.vss.protobuf.VssMessage.pubkey)
}
inline ::std::string* VssMessage::mutable_pubkey() {
  set_has_pubkey();
  // @@protoc_insertion_point(field_mutable:tenon.vss.protobuf.VssMessage.pubkey)
  return pubkey_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* VssMessage::release_pubkey() {
  // @@protoc_insertion_point(field_release:tenon.vss.protobuf.VssMessage.pubkey)
  if (!has_pubkey()) {
    return NULL;
  }
  clear_has_pubkey();
  return pubkey_.ReleaseNonDefaultNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void VssMessage::set_allocated_pubkey(::std::string* pubkey) {
  if (pubkey != NULL) {
    set_has_pubkey();
  } else {
    clear_has_pubkey();
  }
  pubkey_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), pubkey);
  // @@protoc_insertion_point(field_set_allocated:tenon.vss.protobuf.VssMessage.pubkey)
}

// optional bytes sign_ch = 7;
inline bool VssMessage::has_sign_ch() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void VssMessage::set_has_sign_ch() {
  _has_bits_[0] |= 0x00000002u;
}
inline void VssMessage::clear_has_sign_ch() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void VssMessage::clear_sign_ch() {
  sign_ch_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_sign_ch();
}
inline const ::std::string& VssMessage::sign_ch() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.sign_ch)
  return sign_ch_.GetNoArena();
}
inline void VssMessage::set_sign_ch(const ::std::string& value) {
  set_has_sign_ch();
  sign_ch_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.sign_ch)
}
#if LANG_CXX11
inline void VssMessage::set_sign_ch(::std::string&& value) {
  set_has_sign_ch();
  sign_ch_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:tenon.vss.protobuf.VssMessage.sign_ch)
}
#endif
inline void VssMessage::set_sign_ch(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  set_has_sign_ch();
  sign_ch_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:tenon.vss.protobuf.VssMessage.sign_ch)
}
inline void VssMessage::set_sign_ch(const void* value, size_t size) {
  set_has_sign_ch();
  sign_ch_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:tenon.vss.protobuf.VssMessage.sign_ch)
}
inline ::std::string* VssMessage::mutable_sign_ch() {
  set_has_sign_ch();
  // @@protoc_insertion_point(field_mutable:tenon.vss.protobuf.VssMessage.sign_ch)
  return sign_ch_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* VssMessage::release_sign_ch() {
  // @@protoc_insertion_point(field_release:tenon.vss.protobuf.VssMessage.sign_ch)
  if (!has_sign_ch()) {
    return NULL;
  }
  clear_has_sign_ch();
  return sign_ch_.ReleaseNonDefaultNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void VssMessage::set_allocated_sign_ch(::std::string* sign_ch) {
  if (sign_ch != NULL) {
    set_has_sign_ch();
  } else {
    clear_has_sign_ch();
  }
  sign_ch_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), sign_ch);
  // @@protoc_insertion_point(field_set_allocated:tenon.vss.protobuf.VssMessage.sign_ch)
}

// optional bytes sign_res = 8;
inline bool VssMessage::has_sign_res() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void VssMessage::set_has_sign_res() {
  _has_bits_[0] |= 0x00000004u;
}
inline void VssMessage::clear_has_sign_res() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void VssMessage::clear_sign_res() {
  sign_res_.ClearToEmptyNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
  clear_has_sign_res();
}
inline const ::std::string& VssMessage::sign_res() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.sign_res)
  return sign_res_.GetNoArena();
}
inline void VssMessage::set_sign_res(const ::std::string& value) {
  set_has_sign_res();
  sign_res_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), value);
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.sign_res)
}
#if LANG_CXX11
inline void VssMessage::set_sign_res(::std::string&& value) {
  set_has_sign_res();
  sign_res_.SetNoArena(
    &::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::move(value));
  // @@protoc_insertion_point(field_set_rvalue:tenon.vss.protobuf.VssMessage.sign_res)
}
#endif
inline void VssMessage::set_sign_res(const char* value) {
  GOOGLE_DCHECK(value != NULL);
  set_has_sign_res();
  sign_res_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), ::std::string(value));
  // @@protoc_insertion_point(field_set_char:tenon.vss.protobuf.VssMessage.sign_res)
}
inline void VssMessage::set_sign_res(const void* value, size_t size) {
  set_has_sign_res();
  sign_res_.SetNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(),
      ::std::string(reinterpret_cast<const char*>(value), size));
  // @@protoc_insertion_point(field_set_pointer:tenon.vss.protobuf.VssMessage.sign_res)
}
inline ::std::string* VssMessage::mutable_sign_res() {
  set_has_sign_res();
  // @@protoc_insertion_point(field_mutable:tenon.vss.protobuf.VssMessage.sign_res)
  return sign_res_.MutableNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline ::std::string* VssMessage::release_sign_res() {
  // @@protoc_insertion_point(field_release:tenon.vss.protobuf.VssMessage.sign_res)
  if (!has_sign_res()) {
    return NULL;
  }
  clear_has_sign_res();
  return sign_res_.ReleaseNonDefaultNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited());
}
inline void VssMessage::set_allocated_sign_res(::std::string* sign_res) {
  if (sign_res != NULL) {
    set_has_sign_res();
  } else {
    clear_has_sign_res();
  }
  sign_res_.SetAllocatedNoArena(&::google::protobuf::internal::GetEmptyStringAlreadyInited(), sign_res);
  // @@protoc_insertion_point(field_set_allocated:tenon.vss.protobuf.VssMessage.sign_res)
}

// optional uint64 tm_height = 9;
inline bool VssMessage::has_tm_height() const {
  return (_has_bits_[0] & 0x00000080u) != 0;
}
inline void VssMessage::set_has_tm_height() {
  _has_bits_[0] |= 0x00000080u;
}
inline void VssMessage::clear_has_tm_height() {
  _has_bits_[0] &= ~0x00000080u;
}
inline void VssMessage::clear_tm_height() {
  tm_height_ = GOOGLE_ULONGLONG(0);
  clear_has_tm_height();
}
inline ::google::protobuf::uint64 VssMessage::tm_height() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.tm_height)
  return tm_height_;
}
inline void VssMessage::set_tm_height(::google::protobuf::uint64 value) {
  set_has_tm_height();
  tm_height_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.tm_height)
}

// optional uint64 elect_height = 10;
inline bool VssMessage::has_elect_height() const {
  return (_has_bits_[0] & 0x00000100u) != 0;
}
inline void VssMessage::set_has_elect_height() {
  _has_bits_[0] |= 0x00000100u;
}
inline void VssMessage::clear_has_elect_height() {
  _has_bits_[0] &= ~0x00000100u;
}
inline void VssMessage::clear_elect_height() {
  elect_height_ = GOOGLE_ULONGLONG(0);
  clear_has_elect_height();
}
inline ::google::protobuf::uint64 VssMessage::elect_height() const {
  // @@protoc_insertion_point(field_get:tenon.vss.protobuf.VssMessage.elect_height)
  return elect_height_;
}
inline void VssMessage::set_elect_height(::google::protobuf::uint64 value) {
  set_has_elect_height();
  elect_height_ = value;
  // @@protoc_insertion_point(field_set:tenon.vss.protobuf.VssMessage.elect_height)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__

// @@protoc_insertion_point(namespace_scope)

}  // namespace protobuf
}  // namespace vss
}  // namespace tenon

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_INCLUDED_vss_2eproto
