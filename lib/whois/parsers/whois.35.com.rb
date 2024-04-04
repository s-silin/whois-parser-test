#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the whois.35.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class Whois35Com < BaseIcannCompliant
    end

  end
end
