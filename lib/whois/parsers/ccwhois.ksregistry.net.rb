#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared3'


module Whois
  class Parsers

    # Parser for the ccwhois.ksregistry.net server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class CcwhoisKsregistryNet < BaseShared3
    end

  end
end
