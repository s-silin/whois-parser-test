#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.usp.ac.fj server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisUspAcFj < Base

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case $1.downcase
          when "active"
            :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{$1}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^The domain (.+?) was not found!$/)
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expires:\s+(.*)\n/
          parse_time($1)
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain servers:\n\n((.+\n)+)\n/
          $1.split("\n").map do |line|
            name, ipv4 = line.strip.split(/\s+/)
            Parser::Nameserver.new(name: name.downcase, ipv4: ipv4)
          end
        end
      end

      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar
    end
  end
end
