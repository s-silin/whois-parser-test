# frozen_string_literal: true

require_relative 'base'

module Whois
  class Parsers
    class DafabetindiaIn < Base

      property_supported :domain do
        content_for_scanner.slice(/Domain Name:\s*(.+)\n/).to_s.strip
      end

      property_supported :created_date do
        content_for_scanner.slice(/Creation Date:\s*(.+)\n/).to_s.strip
      end

      property_supported :updated_date do
        content_for_scanner.slice(/Updated Date:\s*(.+)\n/).to_s.strip
      end

      property_supported :expiration_date do
        content_for_scanner.slice(/Registry Expiry Date:\s*(.+)\n/).to_s.strip
      end

      property_supported :registrar_name do
        parse_registrar
      end

      private

      def parse_registrar
        registrar_section = content_for_scanner.slice(/Registrar:(.+?)(?:\n\n|$)/m).to_s.strip
        values = build_hash(registrar_section.scan(/(.+?):\s+(.+?)\n/))

        Parser::Registrar.new({
                                name: values['Registrar'],
                                url: values['Registrar URL'],
                                email: values['Registrar Abuse Contact Email'],
                                phone: values['Registrar Abuse Contact Phone']
                              })
      end
    end
  end
end
