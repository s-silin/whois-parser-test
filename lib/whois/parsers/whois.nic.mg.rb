#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


module Whois
  class Parsers

    # Parser for the whois.nic.mg server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicMg < BaseCocca2

      property_supported :status do
        list = Array.wrap(node("Domain Status")).map(&:downcase)
        list.include?("available") ? :available : super()
      end

    end

  end
end
