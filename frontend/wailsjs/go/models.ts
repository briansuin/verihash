export namespace main {
	
	export class BroadcastPublication {
	    id: number;
	    vc_id: string;
	    channel: string;
	    status: string;
	    remote_id: string;
	    remote_url: string;
	    attempt_count: number;
	    last_error: string;
	    last_attempt_at: number;
	    next_retry_at: number;
	    created_at: number;
	    updated_at: number;
	
	    static createFrom(source: any = {}) {
	        return new BroadcastPublication(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.vc_id = source["vc_id"];
	        this.channel = source["channel"];
	        this.status = source["status"];
	        this.remote_id = source["remote_id"];
	        this.remote_url = source["remote_url"];
	        this.attempt_count = source["attempt_count"];
	        this.last_error = source["last_error"];
	        this.last_attempt_at = source["last_attempt_at"];
	        this.next_retry_at = source["next_retry_at"];
	        this.created_at = source["created_at"];
	        this.updated_at = source["updated_at"];
	    }
	}
	export class Config {
	    workspaces: string[];
	    ai_engine: string;
	    model_name: string;
	    api_key: string;
	    base_url: string;
	    auto_start: boolean;
	    cloud_sync_dirs: string[];
	    ignored_patterns: string[];
	    session_ignores: Record<string, Array<string>>;
	    github_pat: string;
	    active_channels: string[];
	    index_gist_id: string;
	    index_gist_url: string;
	    display_name: string;
	    export_dir: string;
	    profile_name: string;
	    profile_website: string;
	    profile_custom: Record<string, string>;
	    window_width: number;
	    window_height: number;
	    window_x: number;
	    window_y: number;
	    window_hidden: boolean;
	
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
	        this.auto_start = source["auto_start"];
	        this.cloud_sync_dirs = source["cloud_sync_dirs"];
	        this.ignored_patterns = source["ignored_patterns"];
	        this.session_ignores = source["session_ignores"];
	        this.github_pat = source["github_pat"];
	        this.active_channels = source["active_channels"];
	        this.index_gist_id = source["index_gist_id"];
	        this.index_gist_url = source["index_gist_url"];
	        this.display_name = source["display_name"];
	        this.export_dir = source["export_dir"];
	        this.profile_name = source["profile_name"];
	        this.profile_website = source["profile_website"];
	        this.profile_custom = source["profile_custom"];
	        this.window_width = source["window_width"];
	        this.window_height = source["window_height"];
	        this.window_x = source["window_x"];
	        this.window_y = source["window_y"];
	        this.window_hidden = source["window_hidden"];
	    }
	}
	export class LedgerEntry {
	    vc_id: string;
	    timestamp: number;
	    project_context: string;
	    ai_insight: string;
	    skill_tags: string;
	    file_paths: string;
	    status: number;
	    vc_hash: string;
	    ai_engine: string;
	    full_vc_json: string;
	
	    static createFrom(source: any = {}) {
	        return new LedgerEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.vc_id = source["vc_id"];
	        this.timestamp = source["timestamp"];
	        this.project_context = source["project_context"];
	        this.ai_insight = source["ai_insight"];
	        this.skill_tags = source["skill_tags"];
	        this.file_paths = source["file_paths"];
	        this.status = source["status"];
	        this.vc_hash = source["vc_hash"];
	        this.ai_engine = source["ai_engine"];
	        this.full_vc_json = source["full_vc_json"];
	    }
	}

}

