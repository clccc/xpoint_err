/*
follow the @path,add new id into the path, gen @newpaths
*/
Object.metaClass.getFarwardPaths_from_condition = { condition_id ->
    println "\n###getFarwardPaths_from_condition"
    println "(1)condition_id = " + condition_id
    MAX_PATHS = 100  // the max number of paths allowed to search
    cnd_true_id = g.v(condition_id).outE("FLOWS_TO").has('flowLabel','True').inV.id.toList()
    cnd_false_id = g.v(condition_id).outE("FLOWS_TO").has('flowLabel','False').inV.id.toList()

    println "(2)cnd_true_id,cnd_flase_id" + cnd_true_id[0] + ',' + cnd_false_id[0]
    true_path = []
    false_path = []
    true_path = getFarwardPaths(cnd_true_id[0])
    false_path = getFarwardPaths(cnd_false_id[0])
    allpaths = []
    allpaths.add(true_path)
    allpaths.add(false_path)
    return allpaths

}
Object.metaClass.getFarwardPaths = { cfgid ->
    println "\n###getFarwardPaths"
    println "(1)cfgid = " + cfgid
    MAX_PATHS = 100  // the max number of paths allowed to search
    paths = [[cfgid]] // currenttly not complete paths
    newpaths = []     // generate follow @paths
    allpaths = []     // all complete paths have been searched
    while (paths.size() != 0)
    {
         println "paths.size() = " + paths.size()
         println "allpaths.size() = " + allpaths.size()

        newpaths = genNewPaths_farward(paths, MAX_PATHS)
        println "newpaths = " + newpaths
        // if it can not gen new path any more, it is time to break loop
        if (newpaths.size ==0)
            break
        // save the complete path to @allpaths, and it not need to search follow the path,
        // so removed it from @newpaths
        i = newpaths.size()-1
        for(;i>=0;i--)
        {
            if( isCompletePath_forward(newpaths[i])){
                allpaths.add(newpaths[i])
                newpaths.remove(i)
            }
        }
        paths = newpaths
        if(allpaths.size() > 100){
            println "error: " + cfgid + " allpaths.size() " + allpaths.size() + " > 100 . The search process was cut off！ "
            return allpaths
        }
    }
    return allpaths
}

//沿着当前位置向后搜索新的节点，属于广度优先遍历
Object.metaClass.genNewPaths_farward = { paths, MAX_PATHS ->
    def newpaths = []
    for(xpath in paths){
        lastid = xpath[xpath.size()-1]
        newids = g.v(lastid).outE('label','FLOWS_TO').inV.id.toList()
        for(xid in newids){
            //if count(xid) >= 2, the xpath has looped 2 times, it must be deleted,and remove this loop path
            counts = countIDs(xpath,xid)
            if (counts >=2){
                flag_invalid = true
                continue
            }
            if (newpaths.size() >= MAX_PATHS){
                break;
            }
            new_path = xpath.plus(xid)
            newpaths.add(new_path)
        }
    }
    newpaths.unique()
    return newpaths
}

Object.metaClass.countIDs = { path,xid ->
    count = 0
    for(id in path)
    {
        if(xid == id)
            count = count +1
    }
    return count
}

/*
check the @path,remove the loop path and  save the complete path in to @allpaths
*/
Object.metaClass.isCompletePath_forward = { path ->
//if the lastid.code = 'ENTRY', the path is a complete path, save it into @allpaths
    println "\n###isCompletePath_forward"
    if(g.v(path[path.size()-1]).type == "CFGExitNode"){
        return true
    }
//else pass
    return false
}

Object.metaClass.printpath = { path ->
    for(id in path)
    {
        print "id = " + id
        print g.v(id).code
        print " -> "
    }
    println "end /n"
}