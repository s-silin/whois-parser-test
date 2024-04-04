# encoding: utf-8

# This file is autogenerated. Do not edit it manually.
# If you want change the content of this file, edit
#
#   /spec/fixtures/responses/whois.educause.edu/edu/property_contact_registrant_with_additional_organization.expected
#
# and regenerate the tests with the following rake task
#
#   $ rake spec:generate
#

require 'spec_helper'
require 'whois/parsers/whois.educause.edu.rb'

describe Whois::Parsers::WhoisEducauseEdu, "property_contact_registrant_with_additional_organization.expected" do

  subject do
    file = fixture("responses", "whois.educause.edu/edu/property_contact_registrant_with_additional_organization.txt")
    part = Whois::Record::Part.new(body: File.read(file))
    described_class.new(part)
  end

  describe "#registrant_contacts" do
    it do
      expect(subject.registrant_contacts).to be_a(Array)
      expect(subject.registrant_contacts.size).to eq(1)
      expect(subject.registrant_contacts[0]).to be_a(Whois::Parser::Contact)
      expect(subject.registrant_contacts[0].type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
      expect(subject.registrant_contacts[0].id).to eq(nil)
      expect(subject.registrant_contacts[0].name).to eq(nil)
      expect(subject.registrant_contacts[0].organization).to eq("Harvard University")
      expect(subject.registrant_contacts[0].address).to eq("HUIT Network Services\n60 Oxford Street")
      expect(subject.registrant_contacts[0].city).to eq("Cambridge")
      expect(subject.registrant_contacts[0].zip).to eq("02138")
      expect(subject.registrant_contacts[0].state).to eq("MA")
      expect(subject.registrant_contacts[0].country).to eq("UNITED STATES")
      expect(subject.registrant_contacts[0].country_code).to eq(nil)
      expect(subject.registrant_contacts[0].phone).to eq(nil)
      expect(subject.registrant_contacts[0].fax).to eq(nil)
      expect(subject.registrant_contacts[0].email).to eq(nil)
    end
  end
end
