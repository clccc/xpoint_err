Object.metaClass._getReturnVarOfCalleeId = { calleeid ->
    println "\n###Info:_getReturnVarOfCalleeId:"
    println "calleeid = " + calleeid
    MAX_PATHS = 100  // the max number of paths allowed to search
    cfgid = g.v(calleeid)._().statements().id.toList().toList()[0]
    calleesite_ids = g.v(calleeid).in.in.id.toList()
    println calleesite_ids
    calleesite_id = calleesite_ids[0]
    if(g.v(cfgid).isCFGNode != "True")
    {
        println "error: g.v("+ cfgid + ").isCFGNode != True)"
        return false
    }
    returnVar_id = 0
    println "calleesite_id: " + calleesite_id
    if((g.v(calleesite_id).type == "AssignmentExpr") && (g.v(calleesite_id).operator.contains("=")))
    {
        returnVar_id = g.v(calleesite_id).outE("IS_AST_PARENT").inV.has('childNum',"0").id.toList()[0]
        println "return_id = " + returnVar_id

    }
    else{
        println "cfgid = " + cfgid
        expstmt_id = g.v(cfgid).outE("IS_AST_PARENT").inV.id.toList()[0]
        if(g.v(expstmt_id).type == "AssignmentExpr")
        {
            returnVar_id = g.v(expstmt_id).outE("IS_AST_PARENT").inV.has('childNum',"0").id
        }
    }
    if(returnVar_id == 0)
        return false
    if(g.v(returnVar_id).type == "Identifier")
    {
        println "ok"
        returnVar_code = g.v(returnVar_id).code
        return returnVar_code
    }
    else
    {
        returnVar_code = g.v(returnVar_id).outE("IS_AST_PARENT").inV.has("type","Identifier").code
        return returnVar_code
    }

}

Object.metaClass._query_checkpoint_of_returnVar = { calleeid, returnVar ->
    println "\n###Info:query_checkpoint_of_returnVar:"
    println "(1):calleeid,returnVar = " + calleeid + " , " + returnVar
    MAX_PATHS = 100  // the max number of paths allowed to search
    cfgid = g.v(calleeid)._().statements().id.toList().toList()[0]
    if (g.v(cfgid).isCFGNode != "True") {
        println " (2): g.v(" + cfgid + ").isCFGNode != True)"
        return false
    }
    println "(3):" + cfgid + " 's tyep is " + g.v(cfgid).type
    if (g.v(cfgid).type == "Condition") {
        return cfgid
    }
    if(returnVar == "Err") {
        return false
    }
    else
    {
        checkid = getCheckpoint_on_var(cfgid,returnVar)
        return checkid
    }
}


Object.metaClass.getCheckpoint_on_var = { cfgid, var ->
    println "\n###Info:getCheckpoint_on_var "
    lastid = cfgid
    newids = g.v(lastid).outE('label','FLOWS_TO').inV.id.toList()
    allid = []
    allid.add(newids)
    println "(1): newids = " + newids
    while(newids.size() != 0) {
        println"loop: 1"
        for (newid in newids) {
            drop_id = []
            println "newid = " + newid
            if (g.v(newid).type == "Condition") {
                println "Is_contain_var_as_symbol-1  " + newid + ", " + var
                if (Is_contain_var_as_symbol(newid, var))
                    println "return " + newid
                    return newid
            } else {
                println "Is_contain_var_as_symbol-2  " + newid + ", " + var
                if (Is_contain_var_as_symbol(newid, var))
                    println "newid, var " + newid + " , " + var
                    drop_id.plus(newid)
            }
        }
        println"loop: 2"
        nex_ids = []
        for (xid in newids){
            if (drop_id.contains(xid)){
                continue
            }
            if(countIDs(allid,xid) > 2) {
                continue
            }
            if(g.v(xid).type != "CFGExitNode"){
                ids = g.v(xid).outE('label','FLOWS_TO').inV.id.toList()
                nex_ids.plus(ids)
                println "len(ids),len(nex_ids) = " + ids.size() + " , " + nex_ids.size()
            }
        }
        println"loop: 3"
        newids = nex_ids
        allid.add(newids)
        if(allid.size() > 2000){
            println "error: getCheckpoint_on_var(" + cfgid + ',' + var + ') > 2000 nodes'
        }
    }
    println "return false"
    return false
}

Object.metaClass.Is_contain_var_as_symbol = { cfgid, var ->
    println "\n###Info:Is_contain_var_as_symbol"
    ids = false
    ids = g.v(cfgid).outE("USE").inV.has('type',"Symbol").has('code',var).id.toList()
    println "(1): cfgid,var, len(gen_ids) = " + cfgid + " , "+ var +" , "+ ids.size()
    if(ids)
    {
        println "return true"
        return true
    }
    println "return false"
    return false
}

Object.metaClass.is_a_isparent_b = { nodeid, var ->
    println "\n###Info:is_a_isparent_b"
    symbols_use = g.v(nodeid).outE("USE").inV.code.toList()
    symbols_def = g.v(nodeid).outE("DEF").inV.code.toList()
    if(symbols_use.contains(var))
        return true
    if(symbols_def.contains(var))
        return true
    return false
}