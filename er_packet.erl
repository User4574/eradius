-module(er_packet).

-export([unpack/1, pack/1, packet_length/1]).

-import(er_tlv, [deparse_tlvs/2]).

-include("eradius.hrl").

unpack(<<
         Code:8,
         Identifier:8,
         Length:16,
         Authenticator:16/binary,
         Attributes:(Length-20)/binary
       >>) ->
  TLVs = er_tlv:parse_tlvs(Attributes, []),
  #packet{
     code=Code,
     identifier=Identifier,
     length=Length,
     authenticator=Authenticator,
     attributes=TLVs
    }.

pack(#packet{
        code=Code,
        identifier=Identifier,
        length=Length,
        authenticator=Authenticator,
        attributes=Attributes
       }) ->
  Deparsed_TLVs = er_tlv:deparse_tlvs(Attributes, <<>>),
  <<
    Code:8,
    Identifier:8,
    Length:16,
    Authenticator:16/binary,
    Deparsed_TLVs/binary
  >>.

packet_length(#packet{attributes=Attrs}) ->
  1 + %code
  1 + %identifier
  2 + %length
  16 + %authenticator
  packet_attributes_length(Attrs).

packet_attributes_length([]) ->
  0;
packet_attributes_length([#tlv{length=L} | Rest]) ->
  L + packet_attributes_length(Rest).
