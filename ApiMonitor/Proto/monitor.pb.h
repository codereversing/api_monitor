// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: monitor.proto

#ifndef PROTOBUF_monitor_2eproto__INCLUDED
#define PROTOBUF_monitor_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2005000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2005000 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/message.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/unknown_field_set.h>
// @@protoc_insertion_point(includes)

namespace ApiMonitor {
namespace ProtoBuf {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_monitor_2eproto();
void protobuf_AssignDesc_monitor_2eproto();
void protobuf_ShutdownFile_monitor_2eproto();

class Call;
class AddHook;
class RemoveHook;
class MonitorMessage;

// ===================================================================

class Call : public ::google::protobuf::Message {
 public:
  Call();
  virtual ~Call();

  Call(const Call& from);

  inline Call& operator=(const Call& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const Call& default_instance();

  void Swap(Call* other);

  // implements Message ----------------------------------------------

  Call* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Call& from);
  void MergeFrom(const Call& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required uint32 uiHookId = 1;
  inline bool has_uihookid() const;
  inline void clear_uihookid();
  static const int kUiHookIdFieldNumber = 1;
  inline ::google::protobuf::uint32 uihookid() const;
  inline void set_uihookid(::google::protobuf::uint32 value);

  // repeated uint64 uiParameter = 2;
  inline int uiparameter_size() const;
  inline void clear_uiparameter();
  static const int kUiParameterFieldNumber = 2;
  inline ::google::protobuf::uint64 uiparameter(int index) const;
  inline void set_uiparameter(int index, ::google::protobuf::uint64 value);
  inline void add_uiparameter(::google::protobuf::uint64 value);
  inline const ::google::protobuf::RepeatedField< ::google::protobuf::uint64 >&
      uiparameter() const;
  inline ::google::protobuf::RepeatedField< ::google::protobuf::uint64 >*
      mutable_uiparameter();

  // @@protoc_insertion_point(class_scope:ApiMonitor.ProtoBuf.Call)
 private:
  inline void set_has_uihookid();
  inline void clear_has_uihookid();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::RepeatedField< ::google::protobuf::uint64 > uiparameter_;
  ::google::protobuf::uint32 uihookid_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(2 + 31) / 32];

  friend void  protobuf_AddDesc_monitor_2eproto();
  friend void protobuf_AssignDesc_monitor_2eproto();
  friend void protobuf_ShutdownFile_monitor_2eproto();

  void InitAsDefaultInstance();
  static Call* default_instance_;
};
// -------------------------------------------------------------------

class AddHook : public ::google::protobuf::Message {
 public:
  AddHook();
  virtual ~AddHook();

  AddHook(const AddHook& from);

  inline AddHook& operator=(const AddHook& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const AddHook& default_instance();

  void Swap(AddHook* other);

  // implements Message ----------------------------------------------

  AddHook* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const AddHook& from);
  void MergeFrom(const AddHook& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required uint32 uiHookId = 1;
  inline bool has_uihookid() const;
  inline void clear_uihookid();
  static const int kUiHookIdFieldNumber = 1;
  inline ::google::protobuf::uint32 uihookid() const;
  inline void set_uihookid(::google::protobuf::uint32 value);

  // required string strDllName = 2;
  inline bool has_strdllname() const;
  inline void clear_strdllname();
  static const int kStrDllNameFieldNumber = 2;
  inline const ::std::string& strdllname() const;
  inline void set_strdllname(const ::std::string& value);
  inline void set_strdllname(const char* value);
  inline void set_strdllname(const char* value, size_t size);
  inline ::std::string* mutable_strdllname();
  inline ::std::string* release_strdllname();
  inline void set_allocated_strdllname(::std::string* strdllname);

  // required string strFunctionName = 3;
  inline bool has_strfunctionname() const;
  inline void clear_strfunctionname();
  static const int kStrFunctionNameFieldNumber = 3;
  inline const ::std::string& strfunctionname() const;
  inline void set_strfunctionname(const ::std::string& value);
  inline void set_strfunctionname(const char* value);
  inline void set_strfunctionname(const char* value, size_t size);
  inline ::std::string* mutable_strfunctionname();
  inline ::std::string* release_strfunctionname();
  inline void set_allocated_strfunctionname(::std::string* strfunctionname);

  // required uint32 uiNumParameters = 4;
  inline bool has_uinumparameters() const;
  inline void clear_uinumparameters();
  static const int kUiNumParametersFieldNumber = 4;
  inline ::google::protobuf::uint32 uinumparameters() const;
  inline void set_uinumparameters(::google::protobuf::uint32 value);

  // @@protoc_insertion_point(class_scope:ApiMonitor.ProtoBuf.AddHook)
 private:
  inline void set_has_uihookid();
  inline void clear_has_uihookid();
  inline void set_has_strdllname();
  inline void clear_has_strdllname();
  inline void set_has_strfunctionname();
  inline void clear_has_strfunctionname();
  inline void set_has_uinumparameters();
  inline void clear_has_uinumparameters();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::std::string* strdllname_;
  ::google::protobuf::uint32 uihookid_;
  ::google::protobuf::uint32 uinumparameters_;
  ::std::string* strfunctionname_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];

  friend void  protobuf_AddDesc_monitor_2eproto();
  friend void protobuf_AssignDesc_monitor_2eproto();
  friend void protobuf_ShutdownFile_monitor_2eproto();

  void InitAsDefaultInstance();
  static AddHook* default_instance_;
};
// -------------------------------------------------------------------

class RemoveHook : public ::google::protobuf::Message {
 public:
  RemoveHook();
  virtual ~RemoveHook();

  RemoveHook(const RemoveHook& from);

  inline RemoveHook& operator=(const RemoveHook& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const RemoveHook& default_instance();

  void Swap(RemoveHook* other);

  // implements Message ----------------------------------------------

  RemoveHook* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const RemoveHook& from);
  void MergeFrom(const RemoveHook& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // required uint32 uiHookId = 1;
  inline bool has_uihookid() const;
  inline void clear_uihookid();
  static const int kUiHookIdFieldNumber = 1;
  inline ::google::protobuf::uint32 uihookid() const;
  inline void set_uihookid(::google::protobuf::uint32 value);

  // @@protoc_insertion_point(class_scope:ApiMonitor.ProtoBuf.RemoveHook)
 private:
  inline void set_has_uihookid();
  inline void clear_has_uihookid();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::google::protobuf::uint32 uihookid_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(1 + 31) / 32];

  friend void  protobuf_AddDesc_monitor_2eproto();
  friend void protobuf_AssignDesc_monitor_2eproto();
  friend void protobuf_ShutdownFile_monitor_2eproto();

  void InitAsDefaultInstance();
  static RemoveHook* default_instance_;
};
// -------------------------------------------------------------------

class MonitorMessage : public ::google::protobuf::Message {
 public:
  MonitorMessage();
  virtual ~MonitorMessage();

  MonitorMessage(const MonitorMessage& from);

  inline MonitorMessage& operator=(const MonitorMessage& from) {
    CopyFrom(from);
    return *this;
  }

  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }

  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }

  static const ::google::protobuf::Descriptor* descriptor();
  static const MonitorMessage& default_instance();

  void Swap(MonitorMessage* other);

  // implements Message ----------------------------------------------

  MonitorMessage* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const MonitorMessage& from);
  void MergeFrom(const MonitorMessage& from);
  void Clear();
  bool IsInitialized() const;

  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:

  ::google::protobuf::Metadata GetMetadata() const;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // optional .ApiMonitor.ProtoBuf.AddHook mAddHook = 1;
  inline bool has_maddhook() const;
  inline void clear_maddhook();
  static const int kMAddHookFieldNumber = 1;
  inline const ::ApiMonitor::ProtoBuf::AddHook& maddhook() const;
  inline ::ApiMonitor::ProtoBuf::AddHook* mutable_maddhook();
  inline ::ApiMonitor::ProtoBuf::AddHook* release_maddhook();
  inline void set_allocated_maddhook(::ApiMonitor::ProtoBuf::AddHook* maddhook);

  // optional .ApiMonitor.ProtoBuf.RemoveHook mRemoveHook = 2;
  inline bool has_mremovehook() const;
  inline void clear_mremovehook();
  static const int kMRemoveHookFieldNumber = 2;
  inline const ::ApiMonitor::ProtoBuf::RemoveHook& mremovehook() const;
  inline ::ApiMonitor::ProtoBuf::RemoveHook* mutable_mremovehook();
  inline ::ApiMonitor::ProtoBuf::RemoveHook* release_mremovehook();
  inline void set_allocated_mremovehook(::ApiMonitor::ProtoBuf::RemoveHook* mremovehook);

  // optional .ApiMonitor.ProtoBuf.Call mCall = 3;
  inline bool has_mcall() const;
  inline void clear_mcall();
  static const int kMCallFieldNumber = 3;
  inline const ::ApiMonitor::ProtoBuf::Call& mcall() const;
  inline ::ApiMonitor::ProtoBuf::Call* mutable_mcall();
  inline ::ApiMonitor::ProtoBuf::Call* release_mcall();
  inline void set_allocated_mcall(::ApiMonitor::ProtoBuf::Call* mcall);

  // optional bool bIsContinue = 4;
  inline bool has_biscontinue() const;
  inline void clear_biscontinue();
  static const int kBIsContinueFieldNumber = 4;
  inline bool biscontinue() const;
  inline void set_biscontinue(bool value);

  // @@protoc_insertion_point(class_scope:ApiMonitor.ProtoBuf.MonitorMessage)
 private:
  inline void set_has_maddhook();
  inline void clear_has_maddhook();
  inline void set_has_mremovehook();
  inline void clear_has_mremovehook();
  inline void set_has_mcall();
  inline void clear_has_mcall();
  inline void set_has_biscontinue();
  inline void clear_has_biscontinue();

  ::google::protobuf::UnknownFieldSet _unknown_fields_;

  ::ApiMonitor::ProtoBuf::AddHook* maddhook_;
  ::ApiMonitor::ProtoBuf::RemoveHook* mremovehook_;
  ::ApiMonitor::ProtoBuf::Call* mcall_;
  bool biscontinue_;

  mutable int _cached_size_;
  ::google::protobuf::uint32 _has_bits_[(4 + 31) / 32];

  friend void  protobuf_AddDesc_monitor_2eproto();
  friend void protobuf_AssignDesc_monitor_2eproto();
  friend void protobuf_ShutdownFile_monitor_2eproto();

  void InitAsDefaultInstance();
  static MonitorMessage* default_instance_;
};
// ===================================================================


// ===================================================================

// Call

// required uint32 uiHookId = 1;
inline bool Call::has_uihookid() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void Call::set_has_uihookid() {
  _has_bits_[0] |= 0x00000001u;
}
inline void Call::clear_has_uihookid() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void Call::clear_uihookid() {
  uihookid_ = 0u;
  clear_has_uihookid();
}
inline ::google::protobuf::uint32 Call::uihookid() const {
  return uihookid_;
}
inline void Call::set_uihookid(::google::protobuf::uint32 value) {
  set_has_uihookid();
  uihookid_ = value;
}

// repeated uint64 uiParameter = 2;
inline int Call::uiparameter_size() const {
  return uiparameter_.size();
}
inline void Call::clear_uiparameter() {
  uiparameter_.Clear();
}
inline ::google::protobuf::uint64 Call::uiparameter(int index) const {
  return uiparameter_.Get(index);
}
inline void Call::set_uiparameter(int index, ::google::protobuf::uint64 value) {
  uiparameter_.Set(index, value);
}
inline void Call::add_uiparameter(::google::protobuf::uint64 value) {
  uiparameter_.Add(value);
}
inline const ::google::protobuf::RepeatedField< ::google::protobuf::uint64 >&
Call::uiparameter() const {
  return uiparameter_;
}
inline ::google::protobuf::RepeatedField< ::google::protobuf::uint64 >*
Call::mutable_uiparameter() {
  return &uiparameter_;
}

// -------------------------------------------------------------------

// AddHook

// required uint32 uiHookId = 1;
inline bool AddHook::has_uihookid() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void AddHook::set_has_uihookid() {
  _has_bits_[0] |= 0x00000001u;
}
inline void AddHook::clear_has_uihookid() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void AddHook::clear_uihookid() {
  uihookid_ = 0u;
  clear_has_uihookid();
}
inline ::google::protobuf::uint32 AddHook::uihookid() const {
  return uihookid_;
}
inline void AddHook::set_uihookid(::google::protobuf::uint32 value) {
  set_has_uihookid();
  uihookid_ = value;
}

// required string strDllName = 2;
inline bool AddHook::has_strdllname() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void AddHook::set_has_strdllname() {
  _has_bits_[0] |= 0x00000002u;
}
inline void AddHook::clear_has_strdllname() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void AddHook::clear_strdllname() {
  if (strdllname_ != &::google::protobuf::internal::kEmptyString) {
    strdllname_->clear();
  }
  clear_has_strdllname();
}
inline const ::std::string& AddHook::strdllname() const {
  return *strdllname_;
}
inline void AddHook::set_strdllname(const ::std::string& value) {
  set_has_strdllname();
  if (strdllname_ == &::google::protobuf::internal::kEmptyString) {
    strdllname_ = new ::std::string;
  }
  strdllname_->assign(value);
}
inline void AddHook::set_strdllname(const char* value) {
  set_has_strdllname();
  if (strdllname_ == &::google::protobuf::internal::kEmptyString) {
    strdllname_ = new ::std::string;
  }
  strdllname_->assign(value);
}
inline void AddHook::set_strdllname(const char* value, size_t size) {
  set_has_strdllname();
  if (strdllname_ == &::google::protobuf::internal::kEmptyString) {
    strdllname_ = new ::std::string;
  }
  strdllname_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* AddHook::mutable_strdllname() {
  set_has_strdllname();
  if (strdllname_ == &::google::protobuf::internal::kEmptyString) {
    strdllname_ = new ::std::string;
  }
  return strdllname_;
}
inline ::std::string* AddHook::release_strdllname() {
  clear_has_strdllname();
  if (strdllname_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = strdllname_;
    strdllname_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void AddHook::set_allocated_strdllname(::std::string* strdllname) {
  if (strdllname_ != &::google::protobuf::internal::kEmptyString) {
    delete strdllname_;
  }
  if (strdllname) {
    set_has_strdllname();
    strdllname_ = strdllname;
  } else {
    clear_has_strdllname();
    strdllname_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// required string strFunctionName = 3;
inline bool AddHook::has_strfunctionname() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void AddHook::set_has_strfunctionname() {
  _has_bits_[0] |= 0x00000004u;
}
inline void AddHook::clear_has_strfunctionname() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void AddHook::clear_strfunctionname() {
  if (strfunctionname_ != &::google::protobuf::internal::kEmptyString) {
    strfunctionname_->clear();
  }
  clear_has_strfunctionname();
}
inline const ::std::string& AddHook::strfunctionname() const {
  return *strfunctionname_;
}
inline void AddHook::set_strfunctionname(const ::std::string& value) {
  set_has_strfunctionname();
  if (strfunctionname_ == &::google::protobuf::internal::kEmptyString) {
    strfunctionname_ = new ::std::string;
  }
  strfunctionname_->assign(value);
}
inline void AddHook::set_strfunctionname(const char* value) {
  set_has_strfunctionname();
  if (strfunctionname_ == &::google::protobuf::internal::kEmptyString) {
    strfunctionname_ = new ::std::string;
  }
  strfunctionname_->assign(value);
}
inline void AddHook::set_strfunctionname(const char* value, size_t size) {
  set_has_strfunctionname();
  if (strfunctionname_ == &::google::protobuf::internal::kEmptyString) {
    strfunctionname_ = new ::std::string;
  }
  strfunctionname_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* AddHook::mutable_strfunctionname() {
  set_has_strfunctionname();
  if (strfunctionname_ == &::google::protobuf::internal::kEmptyString) {
    strfunctionname_ = new ::std::string;
  }
  return strfunctionname_;
}
inline ::std::string* AddHook::release_strfunctionname() {
  clear_has_strfunctionname();
  if (strfunctionname_ == &::google::protobuf::internal::kEmptyString) {
    return NULL;
  } else {
    ::std::string* temp = strfunctionname_;
    strfunctionname_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
    return temp;
  }
}
inline void AddHook::set_allocated_strfunctionname(::std::string* strfunctionname) {
  if (strfunctionname_ != &::google::protobuf::internal::kEmptyString) {
    delete strfunctionname_;
  }
  if (strfunctionname) {
    set_has_strfunctionname();
    strfunctionname_ = strfunctionname;
  } else {
    clear_has_strfunctionname();
    strfunctionname_ = const_cast< ::std::string*>(&::google::protobuf::internal::kEmptyString);
  }
}

// required uint32 uiNumParameters = 4;
inline bool AddHook::has_uinumparameters() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void AddHook::set_has_uinumparameters() {
  _has_bits_[0] |= 0x00000008u;
}
inline void AddHook::clear_has_uinumparameters() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void AddHook::clear_uinumparameters() {
  uinumparameters_ = 0u;
  clear_has_uinumparameters();
}
inline ::google::protobuf::uint32 AddHook::uinumparameters() const {
  return uinumparameters_;
}
inline void AddHook::set_uinumparameters(::google::protobuf::uint32 value) {
  set_has_uinumparameters();
  uinumparameters_ = value;
}

// -------------------------------------------------------------------

// RemoveHook

// required uint32 uiHookId = 1;
inline bool RemoveHook::has_uihookid() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void RemoveHook::set_has_uihookid() {
  _has_bits_[0] |= 0x00000001u;
}
inline void RemoveHook::clear_has_uihookid() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void RemoveHook::clear_uihookid() {
  uihookid_ = 0u;
  clear_has_uihookid();
}
inline ::google::protobuf::uint32 RemoveHook::uihookid() const {
  return uihookid_;
}
inline void RemoveHook::set_uihookid(::google::protobuf::uint32 value) {
  set_has_uihookid();
  uihookid_ = value;
}

// -------------------------------------------------------------------

// MonitorMessage

// optional .ApiMonitor.ProtoBuf.AddHook mAddHook = 1;
inline bool MonitorMessage::has_maddhook() const {
  return (_has_bits_[0] & 0x00000001u) != 0;
}
inline void MonitorMessage::set_has_maddhook() {
  _has_bits_[0] |= 0x00000001u;
}
inline void MonitorMessage::clear_has_maddhook() {
  _has_bits_[0] &= ~0x00000001u;
}
inline void MonitorMessage::clear_maddhook() {
  if (maddhook_ != NULL) maddhook_->::ApiMonitor::ProtoBuf::AddHook::Clear();
  clear_has_maddhook();
}
inline const ::ApiMonitor::ProtoBuf::AddHook& MonitorMessage::maddhook() const {
  return maddhook_ != NULL ? *maddhook_ : *default_instance_->maddhook_;
}
inline ::ApiMonitor::ProtoBuf::AddHook* MonitorMessage::mutable_maddhook() {
  set_has_maddhook();
  if (maddhook_ == NULL) maddhook_ = new ::ApiMonitor::ProtoBuf::AddHook;
  return maddhook_;
}
inline ::ApiMonitor::ProtoBuf::AddHook* MonitorMessage::release_maddhook() {
  clear_has_maddhook();
  ::ApiMonitor::ProtoBuf::AddHook* temp = maddhook_;
  maddhook_ = NULL;
  return temp;
}
inline void MonitorMessage::set_allocated_maddhook(::ApiMonitor::ProtoBuf::AddHook* maddhook) {
  delete maddhook_;
  maddhook_ = maddhook;
  if (maddhook) {
    set_has_maddhook();
  } else {
    clear_has_maddhook();
  }
}

// optional .ApiMonitor.ProtoBuf.RemoveHook mRemoveHook = 2;
inline bool MonitorMessage::has_mremovehook() const {
  return (_has_bits_[0] & 0x00000002u) != 0;
}
inline void MonitorMessage::set_has_mremovehook() {
  _has_bits_[0] |= 0x00000002u;
}
inline void MonitorMessage::clear_has_mremovehook() {
  _has_bits_[0] &= ~0x00000002u;
}
inline void MonitorMessage::clear_mremovehook() {
  if (mremovehook_ != NULL) mremovehook_->::ApiMonitor::ProtoBuf::RemoveHook::Clear();
  clear_has_mremovehook();
}
inline const ::ApiMonitor::ProtoBuf::RemoveHook& MonitorMessage::mremovehook() const {
  return mremovehook_ != NULL ? *mremovehook_ : *default_instance_->mremovehook_;
}
inline ::ApiMonitor::ProtoBuf::RemoveHook* MonitorMessage::mutable_mremovehook() {
  set_has_mremovehook();
  if (mremovehook_ == NULL) mremovehook_ = new ::ApiMonitor::ProtoBuf::RemoveHook;
  return mremovehook_;
}
inline ::ApiMonitor::ProtoBuf::RemoveHook* MonitorMessage::release_mremovehook() {
  clear_has_mremovehook();
  ::ApiMonitor::ProtoBuf::RemoveHook* temp = mremovehook_;
  mremovehook_ = NULL;
  return temp;
}
inline void MonitorMessage::set_allocated_mremovehook(::ApiMonitor::ProtoBuf::RemoveHook* mremovehook) {
  delete mremovehook_;
  mremovehook_ = mremovehook;
  if (mremovehook) {
    set_has_mremovehook();
  } else {
    clear_has_mremovehook();
  }
}

// optional .ApiMonitor.ProtoBuf.Call mCall = 3;
inline bool MonitorMessage::has_mcall() const {
  return (_has_bits_[0] & 0x00000004u) != 0;
}
inline void MonitorMessage::set_has_mcall() {
  _has_bits_[0] |= 0x00000004u;
}
inline void MonitorMessage::clear_has_mcall() {
  _has_bits_[0] &= ~0x00000004u;
}
inline void MonitorMessage::clear_mcall() {
  if (mcall_ != NULL) mcall_->::ApiMonitor::ProtoBuf::Call::Clear();
  clear_has_mcall();
}
inline const ::ApiMonitor::ProtoBuf::Call& MonitorMessage::mcall() const {
  return mcall_ != NULL ? *mcall_ : *default_instance_->mcall_;
}
inline ::ApiMonitor::ProtoBuf::Call* MonitorMessage::mutable_mcall() {
  set_has_mcall();
  if (mcall_ == NULL) mcall_ = new ::ApiMonitor::ProtoBuf::Call;
  return mcall_;
}
inline ::ApiMonitor::ProtoBuf::Call* MonitorMessage::release_mcall() {
  clear_has_mcall();
  ::ApiMonitor::ProtoBuf::Call* temp = mcall_;
  mcall_ = NULL;
  return temp;
}
inline void MonitorMessage::set_allocated_mcall(::ApiMonitor::ProtoBuf::Call* mcall) {
  delete mcall_;
  mcall_ = mcall;
  if (mcall) {
    set_has_mcall();
  } else {
    clear_has_mcall();
  }
}

// optional bool bIsContinue = 4;
inline bool MonitorMessage::has_biscontinue() const {
  return (_has_bits_[0] & 0x00000008u) != 0;
}
inline void MonitorMessage::set_has_biscontinue() {
  _has_bits_[0] |= 0x00000008u;
}
inline void MonitorMessage::clear_has_biscontinue() {
  _has_bits_[0] &= ~0x00000008u;
}
inline void MonitorMessage::clear_biscontinue() {
  biscontinue_ = false;
  clear_has_biscontinue();
}
inline bool MonitorMessage::biscontinue() const {
  return biscontinue_;
}
inline void MonitorMessage::set_biscontinue(bool value) {
  set_has_biscontinue();
  biscontinue_ = value;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace ProtoBuf
}  // namespace ApiMonitor

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_monitor_2eproto__INCLUDED
