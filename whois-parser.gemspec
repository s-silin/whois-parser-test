# -*- encoding: utf-8 -*-
# stub: whois-parser 1.1.0 ruby lib

Gem::Specification.new do |s|
  s.name = "whois-parser".freeze
  s.version = "1.1.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Simone Carletti".freeze]
  s.date = "2018-03-26"
  s.description = "Whois Parser is a WHOIS parser written in pure Ruby. It can parse and convert responses into easy-to-use Ruby objects.".freeze
  s.email = ["weppos@weppos.net".freeze]
  s.files = [".yardopts".freeze, "CHANGELOG.md".freeze, "CONTRIBUTING.md".freeze, "LICENSE.txt".freeze, "README.md".freeze, "lib/whois-parser.rb".freeze, "lib/whois/parser.rb".freeze, "lib/whois/parser/contact.rb".freeze, "lib/whois/parser/errors.rb".freeze, "lib/whois/parser/nameserver.rb".freeze, "lib/whois/parser/registrar.rb".freeze, "lib/whois/parser/super_struct.rb".freeze, "lib/whois/parser/version.rb".freeze, "lib/whois/parser_extensions.rb".freeze, "lib/whois/parser_extensions/whois.rb".freeze, "lib/whois/parser_extensions/whois_parser.rb".freeze, "lib/whois/parser_extensions/whois_record.rb".freeze, "lib/whois/parsers.rb".freeze, "lib/whois/parsers/base.rb".freeze, "lib/whois/parsers/base_afilias.rb".freeze, "lib/whois/parsers/base_afilias2.rb".freeze, "lib/whois/parsers/base_cocca.rb".freeze, "lib/whois/parsers/base_cocca2.rb".freeze, "lib/whois/parsers/base_icann_compliant.rb".freeze, "lib/whois/parsers/base_icb.rb".freeze, "lib/whois/parsers/base_iisse.rb".freeze, "lib/whois/parsers/base_nic_fr.rb".freeze, "lib/whois/parsers/base_shared1.rb".freeze, "lib/whois/parsers/base_shared2.rb".freeze, "lib/whois/parsers/base_shared3.rb".freeze, "lib/whois/parsers/base_verisign.rb".freeze, "lib/whois/parsers/base_whoisd.rb".freeze, "lib/whois/parsers/blank.rb".freeze, "lib/whois/parsers/capetown-whois.registry.net.za.rb".freeze, "lib/whois/parsers/ccwhois.ksregistry.net.rb".freeze, "lib/whois/parsers/ccwhois.verisign-grs.com.rb".freeze, "lib/whois/parsers/coza-whois.registry.net.za.rb".freeze, "lib/whois/parsers/durban-whois.registry.net.za.rb".freeze, "lib/whois/parsers/example.rb".freeze, "lib/whois/parsers/joburg-whois.registry.net.za.rb".freeze, "lib/whois/parsers/kero.yachay.pe.rb".freeze, "lib/whois/parsers/org-whois.registry.net.za.rb".freeze, "lib/whois/parsers/tvwhois.verisign-grs.com.rb".freeze, "lib/whois/parsers/whois.1und1.info.rb".freeze, "lib/whois/parsers/whois.35.com.rb".freeze, "lib/whois/parsers/whois.aeda.net.ae.rb".freeze, "lib/whois/parsers/whois.aero.rb".freeze, "lib/whois/parsers/whois.afilias-grs.info.rb".freeze, "lib/whois/parsers/whois.afilias.net.rb".freeze, "lib/whois/parsers/whois.amnic.net.rb".freeze, "lib/whois/parsers/whois.ascio.com.rb".freeze, "lib/whois/parsers/whois.ati.tn.rb".freeze, "lib/whois/parsers/whois.audns.net.au.rb".freeze, "lib/whois/parsers/whois.ax.rb".freeze, "lib/whois/parsers/whois.biz.rb".freeze, "lib/whois/parsers/whois.bnnic.bn.rb".freeze, "lib/whois/parsers/whois.cat.rb".freeze, "lib/whois/parsers/whois.cctld.by.rb".freeze, "lib/whois/parsers/whois.cctld.uz.rb".freeze, "lib/whois/parsers/whois.cdmon.com.rb".freeze, "lib/whois/parsers/whois.centralnic.com.rb".freeze, "lib/whois/parsers/whois.cira.ca.rb".freeze, "lib/whois/parsers/whois.cmc.iq.rb".freeze, "lib/whois/parsers/whois.cnnic.cn.rb".freeze, "lib/whois/parsers/whois.co.ca.rb".freeze, "lib/whois/parsers/whois.co.pl.rb".freeze, "lib/whois/parsers/whois.co.ug.rb".freeze, "lib/whois/parsers/whois.comlaude.com.rb".freeze, "lib/whois/parsers/whois.corporatedomains.com.rb".freeze, "lib/whois/parsers/whois.denic.de.rb".freeze, "lib/whois/parsers/whois.dk-hostmaster.dk.rb".freeze, "lib/whois/parsers/whois.dns.be.rb".freeze, "lib/whois/parsers/whois.dns.hr.rb".freeze, "lib/whois/parsers/whois.dns.lu.rb".freeze, "lib/whois/parsers/whois.dns.pl.rb".freeze, "lib/whois/parsers/whois.dns.pt.rb".freeze, "lib/whois/parsers/whois.domain-registry.nl.rb".freeze, "lib/whois/parsers/whois.domainregistry.ie.rb".freeze, "lib/whois/parsers/whois.domreg.lt.rb".freeze, "lib/whois/parsers/whois.donuts.co.rb".freeze, "lib/whois/parsers/whois.dot.cf.rb".freeze, "lib/whois/parsers/whois.dot.tk.rb".freeze, "lib/whois/parsers/whois.dotgov.gov.rb".freeze, "lib/whois/parsers/whois.dotmobiregistry.net.rb".freeze, "lib/whois/parsers/whois.dotpostregistry.net.rb".freeze, "lib/whois/parsers/whois.dreamhost.com.rb".freeze, "lib/whois/parsers/whois.educause.edu.rb".freeze, "lib/whois/parsers/whois.eenet.ee.rb".freeze, "lib/whois/parsers/whois.enom.com.rb".freeze, "lib/whois/parsers/whois.eu.org.rb".freeze, "lib/whois/parsers/whois.eu.rb".freeze, "lib/whois/parsers/whois.fi.rb".freeze, "lib/whois/parsers/whois.gandi.net.rb".freeze, "lib/whois/parsers/whois.gg.rb".freeze, "lib/whois/parsers/whois.godaddy.com.rb".freeze, "lib/whois/parsers/whois.gov.za.rb".freeze, "lib/whois/parsers/whois.hkirc.hk.rb".freeze, "lib/whois/parsers/whois.iana.org.rb".freeze, "lib/whois/parsers/whois.iis.nu.rb".freeze, "lib/whois/parsers/whois.iis.se.rb".freeze, "lib/whois/parsers/whois.in.ua.rb".freeze, "lib/whois/parsers/whois.inregistry.net.rb".freeze, "lib/whois/parsers/whois.isnic.is.rb".freeze, "lib/whois/parsers/whois.isoc.org.il.rb".freeze, "lib/whois/parsers/whois.ja.net.rb".freeze, "lib/whois/parsers/whois.je.rb".freeze, "lib/whois/parsers/whois.jprs.jp.rb".freeze, "lib/whois/parsers/whois.kenic.or.ke.rb".freeze, "lib/whois/parsers/whois.kr.rb".freeze, "lib/whois/parsers/whois.markmonitor.com.rb".freeze, "lib/whois/parsers/whois.monic.mo.rb".freeze, "lib/whois/parsers/whois.museum.rb".freeze, "lib/whois/parsers/whois.mynic.my.rb".freeze, "lib/whois/parsers/whois.na-nic.com.na.rb".freeze, "lib/whois/parsers/whois.nc.rb".freeze, "lib/whois/parsers/whois.netcom.cm.rb".freeze, "lib/whois/parsers/whois.networksolutions.com.rb".freeze, "lib/whois/parsers/whois.nic.ac.rb".freeze, "lib/whois/parsers/whois.nic.af.rb".freeze, "lib/whois/parsers/whois.nic.ag.rb".freeze, "lib/whois/parsers/whois.nic.ai.rb".freeze, "lib/whois/parsers/whois.nic.as.rb".freeze, "lib/whois/parsers/whois.nic.asia.rb".freeze, "lib/whois/parsers/whois.nic.at.rb".freeze, "lib/whois/parsers/whois.nic.bj.rb".freeze, "lib/whois/parsers/whois.nic.bo.rb".freeze, "lib/whois/parsers/whois.nic.cd.rb".freeze, "lib/whois/parsers/whois.nic.ch.rb".freeze, "lib/whois/parsers/whois.nic.ci.rb".freeze, "lib/whois/parsers/whois.nic.cl.rb".freeze, "lib/whois/parsers/whois.nic.co.rb".freeze, "lib/whois/parsers/whois.nic.college.rb".freeze, "lib/whois/parsers/whois.nic.coop.rb".freeze, "lib/whois/parsers/whois.nic.cx.rb".freeze, "lib/whois/parsers/whois.nic.cz.rb".freeze, "lib/whois/parsers/whois.nic.design.rb".freeze, "lib/whois/parsers/whois.nic.dm.rb".freeze, "lib/whois/parsers/whois.nic.dz.rb".freeze, "lib/whois/parsers/whois.nic.ec.rb".freeze, "lib/whois/parsers/whois.nic.es.rb".freeze, "lib/whois/parsers/whois.nic.fm.rb".freeze, "lib/whois/parsers/whois.nic.fo.rb".freeze, "lib/whois/parsers/whois.nic.fr.rb".freeze, "lib/whois/parsers/whois.nic.gd.rb".freeze, "lib/whois/parsers/whois.nic.gl.rb".freeze, "lib/whois/parsers/whois.nic.gs.rb".freeze, "lib/whois/parsers/whois.nic.hn.rb".freeze, "lib/whois/parsers/whois.nic.ht.rb".freeze, "lib/whois/parsers/whois.nic.hu.rb".freeze, "lib/whois/parsers/whois.nic.im.rb".freeze, "lib/whois/parsers/whois.nic.io.rb".freeze, "lib/whois/parsers/whois.nic.ir.rb".freeze, "lib/whois/parsers/whois.nic.it.rb".freeze, "lib/whois/parsers/whois.nic.jobs.rb".freeze, "lib/whois/parsers/whois.nic.ki.rb".freeze, "lib/whois/parsers/whois.nic.kz.rb".freeze, "lib/whois/parsers/whois.nic.la.rb".freeze, "lib/whois/parsers/whois.nic.li.rb".freeze, "lib/whois/parsers/whois.nic.lk.rb".freeze, "lib/whois/parsers/whois.nic.lv.rb".freeze, "lib/whois/parsers/whois.nic.ly.rb".freeze, "lib/whois/parsers/whois.nic.md.rb".freeze, "lib/whois/parsers/whois.nic.me.rb".freeze, "lib/whois/parsers/whois.nic.mg.rb".freeze, "lib/whois/parsers/whois.nic.ms.rb".freeze, "lib/whois/parsers/whois.nic.mu.rb".freeze, "lib/whois/parsers/whois.nic.mx.rb".freeze, "lib/whois/parsers/whois.nic.name.rb".freeze, "lib/whois/parsers/whois.nic.net.ng.rb".freeze, "lib/whois/parsers/whois.nic.net.sa.rb".freeze, "lib/whois/parsers/whois.nic.net.sb.rb".freeze, "lib/whois/parsers/whois.nic.nf.rb".freeze, "lib/whois/parsers/whois.nic.org.uy.rb".freeze, "lib/whois/parsers/whois.nic.pm.rb".freeze, "lib/whois/parsers/whois.nic.pr.rb".freeze, "lib/whois/parsers/whois.nic.priv.at.rb".freeze, "lib/whois/parsers/whois.nic.pw.rb".freeze, "lib/whois/parsers/whois.nic.re.rb".freeze, "lib/whois/parsers/whois.nic.sh.rb".freeze, "lib/whois/parsers/whois.nic.sl.rb".freeze, "lib/whois/parsers/whois.nic.sm.rb".freeze, "lib/whois/parsers/whois.nic.sn.rb".freeze, "lib/whois/parsers/whois.nic.so.rb".freeze, "lib/whois/parsers/whois.nic.space.rb".freeze, "lib/whois/parsers/whois.nic.st.rb".freeze, "lib/whois/parsers/whois.nic.tc.rb".freeze, "lib/whois/parsers/whois.nic.tech.rb".freeze, "lib/whois/parsers/whois.nic.tel.rb".freeze, "lib/whois/parsers/whois.nic.tl.rb".freeze, "lib/whois/parsers/whois.nic.tm.rb".freeze, "lib/whois/parsers/whois.nic.tr.rb".freeze, "lib/whois/parsers/whois.nic.travel.rb".freeze, "lib/whois/parsers/whois.nic.uk.rb".freeze, "lib/whois/parsers/whois.nic.us.rb".freeze, "lib/whois/parsers/whois.nic.ve.rb".freeze, "lib/whois/parsers/whois.nic.wf.rb".freeze, "lib/whois/parsers/whois.nic.xxx.rb".freeze, "lib/whois/parsers/whois.nic.xyz.rb".freeze, "lib/whois/parsers/whois.norid.no.rb".freeze, "lib/whois/parsers/whois.pairnic.com.rb".freeze, "lib/whois/parsers/whois.pandi.or.id.rb".freeze, "lib/whois/parsers/whois.pir.org.rb".freeze, "lib/whois/parsers/whois.pnina.ps.rb".freeze, "lib/whois/parsers/whois.register.bg.rb".freeze, "lib/whois/parsers/whois.register.com.rb".freeze, "lib/whois/parsers/whois.register.si.rb".freeze, "lib/whois/parsers/whois.registre.ma.rb".freeze, "lib/whois/parsers/whois.registro.br.rb".freeze, "lib/whois/parsers/whois.registry.gy.rb".freeze, "lib/whois/parsers/whois.registry.hm.rb".freeze, "lib/whois/parsers/whois.registry.om.rb".freeze, "lib/whois/parsers/whois.registry.qa.rb".freeze, "lib/whois/parsers/whois.ripe.net.rb".freeze, "lib/whois/parsers/whois.rnids.rs.rb".freeze, "lib/whois/parsers/whois.rotld.ro.rb".freeze, "lib/whois/parsers/whois.rrpproxy.net.rb".freeze, "lib/whois/parsers/whois.safenames.net.rb".freeze, "lib/whois/parsers/whois.schlund.info.rb".freeze, "lib/whois/parsers/whois.sgnic.sg.rb".freeze, "lib/whois/parsers/whois.sk-nic.sk.rb".freeze, "lib/whois/parsers/whois.smallregistry.net.rb".freeze, "lib/whois/parsers/whois.srs.net.nz.rb".freeze, "lib/whois/parsers/whois.sx.rb".freeze, "lib/whois/parsers/whois.tcinet.ru.rb".freeze, "lib/whois/parsers/whois.thnic.co.th.rb".freeze, "lib/whois/parsers/whois.tld.ee.rb".freeze, "lib/whois/parsers/whois.tld.sy.rb".freeze, "lib/whois/parsers/whois.tonic.to.rb".freeze, "lib/whois/parsers/whois.tucows.com.rb".freeze, "lib/whois/parsers/whois.twnic.net.tw.rb".freeze, "lib/whois/parsers/whois.tznic.or.tz.rb".freeze, "lib/whois/parsers/whois.ua.rb".freeze, "lib/whois/parsers/whois.udag.net.rb".freeze, "lib/whois/parsers/whois.uniregistry.net.rb".freeze, "lib/whois/parsers/whois.usp.ac.fj.rb".freeze, "lib/whois/parsers/whois.verisign-grs.com.rb".freeze, "lib/whois/parsers/whois.website.ws.rb".freeze, "lib/whois/parsers/whois.wildwestdomains.com.rb".freeze, "lib/whois/parsers/whois.yoursrs.com.rb".freeze, "lib/whois/parsers/whois.za.net.rb".freeze, "lib/whois/parsers/whois.za.org.rb".freeze, "lib/whois/parsers/whois1.nic.bi.rb".freeze, "lib/whois/parsers/za_central_registry.rb".freeze, "lib/whois/safe_record.rb".freeze, "lib/whois/scanners/base.rb".freeze, "lib/whois/scanners/base_afilias.rb".freeze, "lib/whois/scanners/base_cocca2.rb".freeze, "lib/whois/scanners/base_icann_compliant.rb".freeze, "lib/whois/scanners/base_iisse.rb".freeze, "lib/whois/scanners/base_shared1.rb".freeze, "lib/whois/scanners/base_shared2.rb".freeze, "lib/whois/scanners/base_shared3.rb".freeze, "lib/whois/scanners/base_whoisd.rb".freeze, "lib/whois/scanners/iana.rb".freeze, "lib/whois/scanners/scannable.rb".freeze, "lib/whois/scanners/verisign.rb".freeze, "lib/whois/scanners/whois.ati.tn.rb".freeze, "lib/whois/scanners/whois.audns.net.au.rb".freeze, "lib/whois/scanners/whois.cctld.by.rb".freeze, "lib/whois/scanners/whois.centralnic.com.rb".freeze, "lib/whois/scanners/whois.cira.ca.rb".freeze, "lib/whois/scanners/whois.cnnic.cn.rb".freeze, "lib/whois/scanners/whois.denic.de.rb".freeze, "lib/whois/scanners/whois.dns.hr.rb".freeze, "lib/whois/scanners/whois.domainregistry.ie.rb".freeze, "lib/whois/scanners/whois.fi.rb".freeze, "lib/whois/scanners/whois.nc.rb".freeze, "lib/whois/scanners/whois.nic.cz.rb".freeze, "lib/whois/scanners/whois.nic.it.rb".freeze, "lib/whois/scanners/whois.pir.org.rb".freeze, "lib/whois/scanners/whois.rnids.rs.rb".freeze, "lib/whois/scanners/whois.smallregistry.net.rb".freeze, "lib/whois/scanners/whois.srs.net.nz.rb".freeze, "lib/whois/scanners/whois.sx.rb".freeze, "lib/whois/scanners/whois.tld.ee.rb".freeze, "lib/whois/scanners/whois.tucows.com.rb".freeze, "lib/whois/scanners/whois.yoursrs.com.rb".freeze, "whois-parser.gemspec".freeze]
  s.homepage = "https://whoisrb.org/".freeze
  s.licenses = ["MIT".freeze]
  s.required_ruby_version = Gem::Requirement.new(">= 2.0.0".freeze)
  s.rubygems_version = "3.4.19".freeze
  s.summary = "A pure Ruby WHOIS parser.".freeze

  s.installed_by_version = "3.4.19" if s.respond_to? :installed_by_version

  s.specification_version = 4

  s.add_runtime_dependency(%q<whois>.freeze, [">= 4.0.6"])
  s.add_runtime_dependency(%q<activesupport>.freeze, [">= 4"])
  s.add_development_dependency(%q<rake>.freeze, [">= 0"])
  s.add_development_dependency(%q<rspec>.freeze, ["~> 3.7"])
  s.add_development_dependency(%q<yard>.freeze, [">= 0"])
end
