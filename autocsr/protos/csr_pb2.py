# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: csr.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='csr.proto',
  package='autocsr',
  syntax='proto3',
  serialized_options=None,
  create_key=_descriptor._internal_create_key,
  serialized_pb=b'\n\tcsr.proto\x12\x07\x61utocsr\"\xe2\x03\n\x19\x43\x65rtificateSigningRequest\x12;\n\x07subject\x18\x01 \x01(\x0b\x32*.autocsr.CertificateSigningRequest.Subject\x12\x10\n\x08key_path\x18\x02 \x01(\t\x12\x13\n\x0boutput_path\x18\x03 \x01(\t\x1a\xe0\x02\n\x07Subject\x12\x13\n\x0b\x63ommon_name\x18\x01 \x01(\t\x12\x19\n\x0c\x63ountry_name\x18\x02 \x01(\tH\x00\x88\x01\x01\x12#\n\x16state_or_province_name\x18\x03 \x01(\tH\x01\x88\x01\x01\x12\x1a\n\rlocality_name\x18\x04 \x01(\tH\x02\x88\x01\x01\x12\x1e\n\x11organization_name\x18\x05 \x01(\tH\x03\x88\x01\x01\x12%\n\x18organizational_unit_name\x18\x06 \x01(\tH\x04\x88\x01\x01\x12\x1a\n\remail_address\x18\x07 \x01(\tH\x05\x88\x01\x01\x42\x0f\n\r_country_nameB\x19\n\x17_state_or_province_nameB\x10\n\x0e_locality_nameB\x14\n\x12_organization_nameB\x1b\n\x19_organizational_unit_nameB\x10\n\x0e_email_addressb\x06proto3'
)




_CERTIFICATESIGNINGREQUEST_SUBJECT = _descriptor.Descriptor(
  name='Subject',
  full_name='autocsr.CertificateSigningRequest.Subject',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='common_name', full_name='autocsr.CertificateSigningRequest.Subject.common_name', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='country_name', full_name='autocsr.CertificateSigningRequest.Subject.country_name', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='state_or_province_name', full_name='autocsr.CertificateSigningRequest.Subject.state_or_province_name', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='locality_name', full_name='autocsr.CertificateSigningRequest.Subject.locality_name', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='organization_name', full_name='autocsr.CertificateSigningRequest.Subject.organization_name', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='organizational_unit_name', full_name='autocsr.CertificateSigningRequest.Subject.organizational_unit_name', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='email_address', full_name='autocsr.CertificateSigningRequest.Subject.email_address', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='_country_name', full_name='autocsr.CertificateSigningRequest.Subject._country_name',
      index=0, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_state_or_province_name', full_name='autocsr.CertificateSigningRequest.Subject._state_or_province_name',
      index=1, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_locality_name', full_name='autocsr.CertificateSigningRequest.Subject._locality_name',
      index=2, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_organization_name', full_name='autocsr.CertificateSigningRequest.Subject._organization_name',
      index=3, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_organizational_unit_name', full_name='autocsr.CertificateSigningRequest.Subject._organizational_unit_name',
      index=4, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
    _descriptor.OneofDescriptor(
      name='_email_address', full_name='autocsr.CertificateSigningRequest.Subject._email_address',
      index=5, containing_type=None,
      create_key=_descriptor._internal_create_key,
    fields=[]),
  ],
  serialized_start=153,
  serialized_end=505,
)

_CERTIFICATESIGNINGREQUEST = _descriptor.Descriptor(
  name='CertificateSigningRequest',
  full_name='autocsr.CertificateSigningRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  create_key=_descriptor._internal_create_key,
  fields=[
    _descriptor.FieldDescriptor(
      name='subject', full_name='autocsr.CertificateSigningRequest.subject', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='key_path', full_name='autocsr.CertificateSigningRequest.key_path', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
    _descriptor.FieldDescriptor(
      name='output_path', full_name='autocsr.CertificateSigningRequest.output_path', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=b"".decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR,  create_key=_descriptor._internal_create_key),
  ],
  extensions=[
  ],
  nested_types=[_CERTIFICATESIGNINGREQUEST_SUBJECT, ],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=23,
  serialized_end=505,
)

_CERTIFICATESIGNINGREQUEST_SUBJECT.containing_type = _CERTIFICATESIGNINGREQUEST
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_country_name'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['country_name'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['country_name'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_country_name']
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_state_or_province_name'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['state_or_province_name'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['state_or_province_name'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_state_or_province_name']
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_locality_name'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['locality_name'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['locality_name'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_locality_name']
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_organization_name'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['organization_name'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['organization_name'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_organization_name']
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_organizational_unit_name'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['organizational_unit_name'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['organizational_unit_name'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_organizational_unit_name']
_CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_email_address'].fields.append(
  _CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['email_address'])
_CERTIFICATESIGNINGREQUEST_SUBJECT.fields_by_name['email_address'].containing_oneof = _CERTIFICATESIGNINGREQUEST_SUBJECT.oneofs_by_name['_email_address']
_CERTIFICATESIGNINGREQUEST.fields_by_name['subject'].message_type = _CERTIFICATESIGNINGREQUEST_SUBJECT
DESCRIPTOR.message_types_by_name['CertificateSigningRequest'] = _CERTIFICATESIGNINGREQUEST
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CertificateSigningRequest = _reflection.GeneratedProtocolMessageType('CertificateSigningRequest', (_message.Message,), {

  'Subject' : _reflection.GeneratedProtocolMessageType('Subject', (_message.Message,), {
    'DESCRIPTOR' : _CERTIFICATESIGNINGREQUEST_SUBJECT,
    '__module__' : 'csr_pb2'
    # @@protoc_insertion_point(class_scope:autocsr.CertificateSigningRequest.Subject)
    })
  ,
  'DESCRIPTOR' : _CERTIFICATESIGNINGREQUEST,
  '__module__' : 'csr_pb2'
  # @@protoc_insertion_point(class_scope:autocsr.CertificateSigningRequest)
  })
_sym_db.RegisterMessage(CertificateSigningRequest)
_sym_db.RegisterMessage(CertificateSigningRequest.Subject)


# @@protoc_insertion_point(module_scope)
