//get checkinfo from @xpath, the source id is xpath[0】
/*
Object.metaClass.getCheckInfoOfPath = { xpath ->
    callsiteId = xpath[0]
    argIds = getArgs(callsiteId)
    symbols = []
    checkinfos = []
    for(argId in argIds){
        symbols.add(getSymbols(argId))
        defInfo = getDefInfo(xpath, callsiteId, argId)
    }
}
*/

Object.metaClass.getArgs= { calleeid ->
    args = g.v(calleeid).in._().callToArguments().id.toList() //.sort()
}

//Object.metaClass.getDefChain= { xpath, callsiteId, argId ->
    //defIDS = g.v(callsiteId).inE('type','REACHES').outV.filter{xpath.toString().contains(it.id.toString())}.transform{[it.id, callsiteid]}
//}

def controls_loop = []
//Todo: is this right?
Object.metaClass.getControlsFromCfgId_body = { cfg_id ->
    /**多个直接控制条件语句
     def control_ids = g.v(cfg_id).inE.has('label','CONTROLS').outV.id.toList()
     for(controlid in control_ids){
     if(controlid.code == "ENTRY"){
     break;
     }
     else {
     CallsiteInfo.conditionslist.add(controlid)
     control_ids.add(g.v(controlid).inE.has('label','CONTROLS').outV.id.toList())
     }
     }
     **/
    //假定每个CFG节点的直接控制条件语句只会有一个
    def control_ids = g.v(cfg_id).inE.has('label','CONTROLS').outV.id.toList()
    for(c in control_ids){
        if(g.v(c).code != "ENTRY"){
            if(controls_loop.contains(c))
                continue
            controls_loop.add(c)
            getControlsFromCfgId_body(c)
        }
    }
    return controls_loop

}

Object.metaClass.getControlsFromCfgId = { cfg_id ->
    controls = getControlsFromCfgId_body(cfg_id)
    controls_loop = []
    return controls
}