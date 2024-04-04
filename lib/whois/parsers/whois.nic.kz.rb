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

    # Parser for the whois.nic.kz server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    class WhoisNicKz < Base

      property_supported :status do
        if content_for_scanner =~ /Domain status : ((.+\n)+)\s+\n/
          $1.split("\n").map { |value| value.split("-").first.strip }
        else
          nil
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /Nothing found for this query/)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Domain created: (.+)\n/
          parse_time($1)
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Last modified : (.+)\n/ && !(value = $1).empty?
          parse_time(value)
        end
      end

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/^\w+ server\.+:\s(.*)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :registrar
    end
  end
end
