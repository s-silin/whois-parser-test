#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.afilias-grs.info server.
    class WhoisAfiliasGrsInfo < BaseAfilias
      self.scanner = Scanners::BaseAfilias, {
        pattern_disclaimer: /^Access to/,
      }
    end

  end
end
