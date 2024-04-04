#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2018 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.nic.it.rb'


module Whois
  class Parsers

    # Parser for the whois.nic.it server.
    class WhoisNicIt < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisNicIt


      property_supported :disclaimer do
        node("Disclaimer")
      end


      property_supported :domain do
        node("Domain") { |str| str.downcase }
      end

      property_not_supported :domain_id


      property_supported :status do
        case s = node("Status").to_s.downcase
        when /^ok/, /\bclient/
          :registered
        when "grace-period", "no-provider"
          :registered
        when /^pendingupdate/
          :registered
        when /^pendingtransfer/
          :registered
        when /redemption\-/
          :redemption
        when "pending-delete"
          :redemption
        # The domain will be deleted in 5 days
        when /^pendingdelete/
          :redemption
        when "unassignable"
          :unavailable
        when "reserved"
          :reserved
        when "available"
          :available
        when /^inactive/
          :inactive
        else
          Whois::Parser.bug!(ParserError, "Unknown status `#{s}'.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        !available? &&
        !unavailable?
      end

      # NEWPROPERTY
      def unavailable?
        status == :unavailable
      end


      property_supported :created_on do
        node("Created") { |str| parse_time(str) }
      end

      property_supported :updated_on do
        node("Last Update") { |str| parse_time(str) }
      end

      property_supported :expires_on do
        node("Expire Date") { |str| parse_time(str) }
      end


      property_supported :registrar do
        node("Registrar") do |str|
          Parser::Registrar.new(
              id:           str["Name"],
              name:         str["Name"],
              organization: str["Organization"],
              url:          str["Web"]
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin Contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Technical Contacts", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("Nameservers")).map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      # Checks whether this response contains a message
      # that can be reconducted to a "WHOIS Server Unavailable" status.
      #
      # @return [Boolean]
      def response_unavailable?
        !!node("response:unavailable")
      end


      private

      def build_contact(element, type)
        node(element) do |str|
          address = (str["Address"] || "").split("\n")
          company = address.size == 6 ? address.shift : nil
          Parser::Contact.new(
            :id           => str["ContactID"],
            :type         => type,
            :name         => str["Name"],
            :organization => str["Organization"] || company,
            :address      => address[0],
            :city         => address[1],
            :zip          => address[2],
            :state        => address[3],
            :country_code => address[4],
            :created_on   => str["Created"] ? parse_time(str["Created"]) : nil,
            :updated_on   => str["Last Update"] ? parse_time(str["Last Update"]) : nil
          )
        end
      end

    end

  end
end
