#!/usr/bin/python

import re, sys
from argparse import ArgumentParser

class FWALL:

    def __init__( self ):
        
        self.obj = {
            'regex' : re.compile( "^([\w]{3}\s+[\d]{1,2})\s([\d]{2}:[\d]{2}:[\d]{2}).*SRC\=(.*?)\s.*PROTO\=(.*?)\s.*DPT\=(.*?)\s.*" ),
            'hits'  : dict(),
            'rfcnt' : 0,
        }

    def build_dataset( self, timestamp = False ):
        for host in self.yield_host():
            self.append_record( host, timestamp )
        

    def generate_host_report( self, timestamp = False, ports = False ):

        self.build_dataset( timestamp )

        for host, totalHits in self.sort_active():
            print '[+] {:15} : {} Total hits'.format( host, totalHits )
            if ports: self.generate_port_report( self.obj[ 'hits' ][ host ], timestamp )


    def generate_port_report( self, hostObj, timestamp = False ):

        for proto in [ 'TCP', 'UDP' ]:
            if hostObj.has_key( proto ):
                print '\t[ {} ]'.format( proto )

                for port in hostObj[ proto ].keys():
                    print '\t\t Port: {:5} => {} Hits'.format( port, hostObj[ proto ][ port ][ 0 ] )
                    # INSERT TIMESTAMP SAMPLE HERE IF TIMESTAMP = True
                print '\n'

    def generate_quick_report( self ):
        self.build_dataset()
        hits = self.obj[ 'hits' ]

        for host, totalHits in self.sort_active():

            plist = []
            for proto in [ 'TCP', 'UDP' ]:
                if hits[ host ].has_key( proto ):
                    for port in sorted( hits[ host ][ proto ], key=hits[ host ][ proto ].get, reverse=True ):
                        plist.append( '{:5} #{}'.format( port, hits[ host ][ proto ][ port ][0] ) )

            print '[+] {:15} => {}'.format( host, ', '.join( plist ) )


    def sort_active( self ):
        unsorted_hosts, hits = [], self.obj[ 'hits' ]

        for host in hits.keys():
            cnt = 0

            for proto in [ 'TCP', 'UDP' ]:
                if hits[ host ].has_key( proto ):
                    for port in hits[ host ][ proto ].keys():
                        cnt += hits[ host ][ proto ][ port ][ 0 ]

            unsorted_hosts.append( ( host, cnt ) )


        # Return host list sorted by port filter count
        return sorted( unsorted_hosts, key=lambda x: x[1], reverse=True )
        
    def yield_host( self ):
        
        input_data = sys.stdin.readlines()

        for logEntry in input_data:
            try:
                hostdata = self.obj[ 'regex' ].match( logEntry ).groups()

                yield hostdata 
            except Exception as SloppyRegex:
                self.obj[ 'rfcnt' ] += 1
                continue

    def append_record( self, hostdata, timestamp=False ):
        """
            hostdata = [ date, time, ip, proto, port ]
                          0     1    2     3     4 
        """

        ( date, time, host, proto, port ) = hostdata 

        # Have we seen this host before?
        if self.obj[ 'hits' ].has_key( host ):
            hostObj = self.obj[ 'hits' ][ host ]

            # We have seen this host, how about the protocol
            if hostObj.has_key( proto ):
                protoObj = hostObj[ proto ]

                # We have seen this protocol before, how about the port
                if protoObj.has_key( port ):
                    protoObj[ port ][ 0 ] += 1
                    if timestamp: protoObj.append( '{} {}'.format( date, time ) )

                # We have not seen this port before
                else:
                    protoObj[ port ] = [ 1, ]
                    if timestamp: protoObj.append( '{} {}'.format( date, time ) )

            # We have not seen this protocol before
            else:
                hostObj[ proto ] = { port : [ 1, ], }
                if timestamp: hostObj[ proto ][ port ].append( '{} {}'.format( date, time ) )

        # We have not seen this host before
        else:
            self.obj[ 'hits' ][ host ] = { proto: { port : [ 1, ] }, }
            if timestamp: self.obj[ 'hits' ][ host ][ proto ][ port ].append( '{} {}'.format( date, time ) )


if __name__ == '__main__':

    fwall  = FWALL()
    parser = ArgumentParser( description="Firewall log parser; generates quick or host reports exclusively." )

    parser.add_argument( '-H', '--host',      action='store_true', dest='host',
                         default=False, help="Report on parsed Host Data" )

    parser.add_argument( '-p', '--port',      action='store_true', dest='port',
                         default=False, help="Report on parsed port data" )

    parser.add_argument( '-q', '--quick',     action='store_true', dest='quick',
                         default=False, help="Generate Quick Report, can not be part of a Host report" )

    parser.add_argument( '-t', '--timestamp', action='store_true', dest='timestamp',
                         default=False, help="Report with timestamps (Increases Resource Consumption Considerably)" )

    args = parser.parse_args()

    try:
        if args.quick and args.host:
            parser.print_help()
            print '\n[!] Quick And Host Reporting Exclusive, Please refer to the help section.\n'
        elif args.quick:
            fwall.generate_quick_report()
        elif args.host:
            fwall.generate_host_report( args.timestamp, args.port ) 
        else:
            parser.print_help()
    except IOError as CmdPipingBuggyness:
        pass
