all: BGP.out

BGP.out: main.cpp AS.h AS.cpp ASList.h ASList.cpp BGPGraph.h BGPGraph.cpp GraphProcessor.h GraphProcessor.cpp Log.h Log.cpp ParallelGraphProcessor.h ParallelGraphProcessor.cpp Route.h Route.cpp RouteFilter.h RouteFilter.cpp RoutingTable.h RoutingTable.cpp SortedASVector.h SortedASVector.cpp Utils.h Utils.cpp
	 g++ -g -std=c++0x -static-libstdc++ -O3 main.cpp AS.h AS.cpp ASList.h ASList.cpp BGPGraph.h BGPGraph.cpp GraphProcessor.h GraphProcessor.cpp Log.h Log.cpp ParallelGraphProcessor.h ParallelGraphProcessor.cpp Route.h Route.cpp RouteFilter.h RouteFilter.cpp RoutingTable.h RoutingTable.cpp SortedASVector.h SortedASVector.cpp Utils.h Utils.cpp -lpthread -Wall -o BGP.out 
