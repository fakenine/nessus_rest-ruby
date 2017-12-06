# = nessus_rest.rb: communicate with Nessus(6+) over JSON REST interface
#
# Author:: Vlatko Kosturjak
#
# (C) Vlatko Kosturjak, Kost. Distributed under MIT license.
#
# == What is this library?
#
# This library is used for communication with Nessus over JSON REST interface.
# You can start, stop, pause and resume scan. Watch progress and status of scan,
# download report, etc.
#
# == Requirements
#
# Required libraries are standard Ruby libraries: uri, net/https and json.
#
# == Usage:
#
#   require 'nessus_rest'
#
#   n = NessusREST::Client.new(url: 'https://localhost:8834', username: 'user', password: 'password')
#   qs = n.scan_quick_template('basic','name-of-scan','localhost')
#   scanid = qs['scan']['id']
#   n.scan_wait4finish(scanid)
#   n.report_download_file(scanid,'csv','myscanreport.csv')
#

require 'nessus_rest/client'

module NessusREST
end
