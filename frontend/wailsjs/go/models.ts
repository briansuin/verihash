export namespace main {
	
	export class Config {
	    workspaces: string[];
	    ai_engine: string;
	    model_name: string;
	    api_key: string;
	    base_url: string;
	
	    static createFrom(source: any = {}) {
	        return new Config(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.workspaces = source["workspaces"];
	        this.ai_engine = source["ai_engine"];
	        this.model_name = source["model_name"];
	        this.api_key = source["api_key"];
	        this.base_url = source["base_url"];
	    }
	}
	export class LedgerEntry {
	    vc_id: string;
	    timestamp: number;
	    project_context: string;
	    ai_insight: string;
	    file_paths: string;
	    status: number;
	    vc_hash: string;
	
	    static createFrom(source: any = {}) {
	        return new LedgerEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vc_id = source["vc_id"];
	        this.timestamp = source["timestamp"];
	        this.project_context = source["project_context"];
	        this.ai_insight = source["ai_insight"];
	        this.file_paths = source["file_paths"];
	        this.status = source["status"];
	        this.vc_hash = source["vc_hash"];
	    }
	}

}

