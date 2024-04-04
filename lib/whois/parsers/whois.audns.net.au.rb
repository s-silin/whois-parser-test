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

    # Parser for the whois.audns.net.au server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAudnsNetAu < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^NOT FOUND\n/,
      }

      property_not_supported :disclaimer

      property_supported :updated_on do
        node("Last Modified") { |value| parse_time(value) }
      end

      property_supported :registrar do
        node("Registrar Name") do |str|
          Parser::Registrar.new({
            name: str,
          })
        end
      end


      property_supported :registrant_contacts do
        contact = build_contact("Registrant Contact", Parser::Contact::TYPE_REGISTRANT)
        contact.organization = node("Registrant") if contact
        contact
      end

      property_not_supported :admin_contacts

      property_supported :technical_contacts do
        build_contact("Tech Contact", Parser::Contact::TYPE_TECHNICAL)
      end


      private

      def build_contact(element, type)
        node("#{element} ID") do |str|
          Parser::Contact.new({
            type:         type,
            id:           str,
            name:         node("#{element} Name"),
            organization: nil,
            address:      nil,
            city:         nil,
            zip:          nil,
            state:        nil,
            country:      nil,
            phone:        nil,
            fax:          nil,
            email:        node("#{element} Email"),
          })
        end
      end

    end

  end
end
