/*
 *  Copyright 2021-2021 yggo Technologies and contributors.
 *
 *  此源代码的使用受 GNU AFFERO GENERAL PUBLIC LICENSE version 3 许可证的约束, 可以在以下链接找到该许可证.
 *  Use of this source code is governed by the GNU AGPLv3 license that can be found through the following link.
 *
 *  https://github.com/yggo/androidqq-sniffer/blob/main/LICENSE
 */

// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: AndroidDeviceInfo.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace YgAndroidQQSniffer.TLVParser.TLV52D {

  /// <summary>Holder for reflection information generated from AndroidDeviceInfo.proto</summary>
  public static partial class AndroidDeviceInfoReflection {

    #region Descriptor
    /// <summary>File descriptor for AndroidDeviceInfo.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static AndroidDeviceInfoReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChdBbmRyb2lkRGV2aWNlSW5mby5wcm90bxIjWWdBbmRyb2lkUVFTbmlmZmVy",
            "LlRMVlBhcnNlci5UTFY1MkQivAEKCkRldmljZUluZm8SEgoKYm9vdGxvYWRl",
            "chgBIAEoDBITCgtwcm9jVmVyc2lvbhgCIAEoDBIQCghjb2RlTmFtZRgDIAEo",
            "DBITCgtpbmNyZW1lbnRhbBgEIAEoDBITCgtmaW5nZXJwcmludBgFIAEoDBIO",
            "CgZib290SUQYBiABKAwSEQoJYW5kcm9pZElEGAcgASgMEhAKCGJhc2VCYW5k",
            "GAggASgMEhQKDGlubmVyVmVyc2lvbhgJIAEoDGIGcHJvdG8z"));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(null, null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::YgAndroidQQSniffer.TLVParser.TLV52D.DeviceInfo), global::YgAndroidQQSniffer.TLVParser.TLV52D.DeviceInfo.Parser, new[]{ "Bootloader", "ProcVersion", "CodeName", "Incremental", "Fingerprint", "BootID", "AndroidID", "BaseBand", "InnerVersion" }, null, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  public sealed partial class DeviceInfo : pb::IMessage<DeviceInfo> {
    private static readonly pb::MessageParser<DeviceInfo> _parser = new pb::MessageParser<DeviceInfo>(() => new DeviceInfo());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pb::MessageParser<DeviceInfo> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::YgAndroidQQSniffer.TLVParser.TLV52D.AndroidDeviceInfoReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public DeviceInfo() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public DeviceInfo(DeviceInfo other) : this() {
      bootloader_ = other.bootloader_;
      procVersion_ = other.procVersion_;
      codeName_ = other.codeName_;
      incremental_ = other.incremental_;
      fingerprint_ = other.fingerprint_;
      bootID_ = other.bootID_;
      androidID_ = other.androidID_;
      baseBand_ = other.baseBand_;
      innerVersion_ = other.innerVersion_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public DeviceInfo Clone() {
      return new DeviceInfo(this);
    }

    /// <summary>Field number for the "bootloader" field.</summary>
    public const int BootloaderFieldNumber = 1;
    private pb::ByteString bootloader_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString Bootloader {
      get { return bootloader_; }
      set {
        bootloader_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "procVersion" field.</summary>
    public const int ProcVersionFieldNumber = 2;
    private pb::ByteString procVersion_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString ProcVersion {
      get { return procVersion_; }
      set {
        procVersion_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "codeName" field.</summary>
    public const int CodeNameFieldNumber = 3;
    private pb::ByteString codeName_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString CodeName {
      get { return codeName_; }
      set {
        codeName_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "incremental" field.</summary>
    public const int IncrementalFieldNumber = 4;
    private pb::ByteString incremental_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString Incremental {
      get { return incremental_; }
      set {
        incremental_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "fingerprint" field.</summary>
    public const int FingerprintFieldNumber = 5;
    private pb::ByteString fingerprint_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString Fingerprint {
      get { return fingerprint_; }
      set {
        fingerprint_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "bootID" field.</summary>
    public const int BootIDFieldNumber = 6;
    private pb::ByteString bootID_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString BootID {
      get { return bootID_; }
      set {
        bootID_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "androidID" field.</summary>
    public const int AndroidIDFieldNumber = 7;
    private pb::ByteString androidID_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString AndroidID {
      get { return androidID_; }
      set {
        androidID_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "baseBand" field.</summary>
    public const int BaseBandFieldNumber = 8;
    private pb::ByteString baseBand_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString BaseBand {
      get { return baseBand_; }
      set {
        baseBand_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "innerVersion" field.</summary>
    public const int InnerVersionFieldNumber = 9;
    private pb::ByteString innerVersion_ = pb::ByteString.Empty;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString InnerVersion {
      get { return innerVersion_; }
      set {
        innerVersion_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override bool Equals(object other) {
      return Equals(other as DeviceInfo);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public bool Equals(DeviceInfo other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Bootloader != other.Bootloader) return false;
      if (ProcVersion != other.ProcVersion) return false;
      if (CodeName != other.CodeName) return false;
      if (Incremental != other.Incremental) return false;
      if (Fingerprint != other.Fingerprint) return false;
      if (BootID != other.BootID) return false;
      if (AndroidID != other.AndroidID) return false;
      if (BaseBand != other.BaseBand) return false;
      if (InnerVersion != other.InnerVersion) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override int GetHashCode() {
      int hash = 1;
      if (Bootloader.Length != 0) hash ^= Bootloader.GetHashCode();
      if (ProcVersion.Length != 0) hash ^= ProcVersion.GetHashCode();
      if (CodeName.Length != 0) hash ^= CodeName.GetHashCode();
      if (Incremental.Length != 0) hash ^= Incremental.GetHashCode();
      if (Fingerprint.Length != 0) hash ^= Fingerprint.GetHashCode();
      if (BootID.Length != 0) hash ^= BootID.GetHashCode();
      if (AndroidID.Length != 0) hash ^= AndroidID.GetHashCode();
      if (BaseBand.Length != 0) hash ^= BaseBand.GetHashCode();
      if (InnerVersion.Length != 0) hash ^= InnerVersion.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void WriteTo(pb::CodedOutputStream output) {
      if (Bootloader.Length != 0) {
        output.WriteRawTag(10);
        output.WriteBytes(Bootloader);
      }
      if (ProcVersion.Length != 0) {
        output.WriteRawTag(18);
        output.WriteBytes(ProcVersion);
      }
      if (CodeName.Length != 0) {
        output.WriteRawTag(26);
        output.WriteBytes(CodeName);
      }
      if (Incremental.Length != 0) {
        output.WriteRawTag(34);
        output.WriteBytes(Incremental);
      }
      if (Fingerprint.Length != 0) {
        output.WriteRawTag(42);
        output.WriteBytes(Fingerprint);
      }
      if (BootID.Length != 0) {
        output.WriteRawTag(50);
        output.WriteBytes(BootID);
      }
      if (AndroidID.Length != 0) {
        output.WriteRawTag(58);
        output.WriteBytes(AndroidID);
      }
      if (BaseBand.Length != 0) {
        output.WriteRawTag(66);
        output.WriteBytes(BaseBand);
      }
      if (InnerVersion.Length != 0) {
        output.WriteRawTag(74);
        output.WriteBytes(InnerVersion);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public int CalculateSize() {
      int size = 0;
      if (Bootloader.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Bootloader);
      }
      if (ProcVersion.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(ProcVersion);
      }
      if (CodeName.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(CodeName);
      }
      if (Incremental.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Incremental);
      }
      if (Fingerprint.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Fingerprint);
      }
      if (BootID.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(BootID);
      }
      if (AndroidID.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(AndroidID);
      }
      if (BaseBand.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(BaseBand);
      }
      if (InnerVersion.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(InnerVersion);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(DeviceInfo other) {
      if (other == null) {
        return;
      }
      if (other.Bootloader.Length != 0) {
        Bootloader = other.Bootloader;
      }
      if (other.ProcVersion.Length != 0) {
        ProcVersion = other.ProcVersion;
      }
      if (other.CodeName.Length != 0) {
        CodeName = other.CodeName;
      }
      if (other.Incremental.Length != 0) {
        Incremental = other.Incremental;
      }
      if (other.Fingerprint.Length != 0) {
        Fingerprint = other.Fingerprint;
      }
      if (other.BootID.Length != 0) {
        BootID = other.BootID;
      }
      if (other.AndroidID.Length != 0) {
        AndroidID = other.AndroidID;
      }
      if (other.BaseBand.Length != 0) {
        BaseBand = other.BaseBand;
      }
      if (other.InnerVersion.Length != 0) {
        InnerVersion = other.InnerVersion;
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(pb::CodedInputStream input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            Bootloader = input.ReadBytes();
            break;
          }
          case 18: {
            ProcVersion = input.ReadBytes();
            break;
          }
          case 26: {
            CodeName = input.ReadBytes();
            break;
          }
          case 34: {
            Incremental = input.ReadBytes();
            break;
          }
          case 42: {
            Fingerprint = input.ReadBytes();
            break;
          }
          case 50: {
            BootID = input.ReadBytes();
            break;
          }
          case 58: {
            AndroidID = input.ReadBytes();
            break;
          }
          case 66: {
            BaseBand = input.ReadBytes();
            break;
          }
          case 74: {
            InnerVersion = input.ReadBytes();
            break;
          }
        }
      }
    }

  }

  #endregion

}

#endregion Designer generated code
