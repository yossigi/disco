# bgp-sim

## data sources
* http://data.caida.org/datasets/as-relationships/serial-1/20190801.as-rel.txt.bz2 -> BGPGraph::kASRelationshipsFile
* https://www.iana.org/assignments/as-numbers/as-numbers-1.csv -> BGPGraph::kASRegionsFile("../data/as-geo.csv");
* https://www.iana.org/assignments/as-numbers/as-numbers-2.csv -> BGPGraph::kASRegionsFile32bit
* BGPGraph::kASExtraRelationshipsFile("../data/AS_link_extended.txt"); # TODO: Find new version or drop it
* BGPGraph::kASExtraRelationshipsCaidaFile("../data/mlp-Dec-2014.txt");
* BGPGraph::kVantagePointsFile # parsed from RouteViews & RIPE RIS


## test:
./BGP.out 1000 all all 0 0 0 0 false false 1 deployments_prob_40.log 4 0
