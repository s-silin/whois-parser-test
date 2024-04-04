#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.dns.hr.rb'


module Whois
  class Parsers

    # Parser for the whois.dns.hr server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsHr < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisDnsHr

      property_not_supported :disclaimer

      property_supported :domain do
        node("Domain Name")
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Registrar Registration Expiration Date") { |value| parse_time(value) }
      end


      property_not_supported :registrar

      property_supported :registrant_contacts do
        node("Registrant Name") do |name|
          Parser::Contact.new(
            :type         => Parser::Contact::TYPE_REGISTRANT,
            :id           => nil,
            :name         => name,
            :organization => nil,
            :address      => node('Registrant Street'),
            :city         => node('Registrant City'),
            :zip          => node('Registrant Postal Code'),
            :state        => node('Registrant State/Province'),
            :country      => nil,
            :phone        => nil,
            :fax          => nil,
            :email        => nil
          )
        end
      end

      property_not_supported :admin_contacts
      property_not_supported :technical_contacts

      property_supported :nameservers do
        Array.wrap(node("Name Server") || node("Name Servers")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

    end

  end
end
