import streamlit as st
import sqlite3
import json
import os
import time
import datetime
import pandas as pd
import database
import oracle_engine
import config_manager

# 1. Page Initialization
st.set_page_config(page_title="VeriHash Node Prime", layout="wide")

# Custom UI Styling (Cyberpunk Geek Aesthetic)
st.markdown("""
<style>
    .stApp {
        background-color: #0b0f19;
    }
    
    /* Apply base text color ONLY to the main area, preserving sidebar */
    section[data-testid="stMain"] {
        color: #e0e0e0;
    }
    
    h1, h2, h3 {
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Neon effect for main dark area headers */
    section[data-testid="stMain"] h1, 
    section[data-testid="stMain"] h2, 
    section[data-testid="stMain"] h3 {
        color: #00ffcc !important;
        text-shadow: 0 0 5px #00ffcc;
    }
    
    /* Readable dark teal color for sidebar headers on light background */
    section[data-testid="stSidebar"] h1, 
    section[data-testid="stSidebar"] h2, 
    section[data-testid="stSidebar"] h3 {
        color: #005a4a !important;
        text-shadow: none;
    }
    .stButton>button {
        background-color: #00ffcc;
        color: #0b0f19 !important;
        border: 2px solid #00ffcc;
        border-radius: 4px;
        font-family: 'Courier New', Courier, monospace;
        font-weight: bolder;
        font-size: 1.2rem;
        transition: all 0.3s ease;
        text-shadow: none;
    }
    .stButton>button p {
        color: #0b0f19 !important;
    }
    .stButton>button:hover {
        background-color: transparent;
        color: #00ffcc !important;
        border: 2px solid #00ffcc;
        box-shadow: 0 0 10px #00ffcc;
    }
    .stButton>button:hover p {
        color: #00ffcc !important;
    }
    .stAlert {
        border-left-color: #00ffcc !important;
    }
    
    /* Target specific text in the main dark area tightly */
    section[data-testid="stMain"] .stTabs [data-baseweb="tab"] {
        color: #e0e0e0 !important;
    }
    section[data-testid="stMain"] .stTabs [aria-selected="true"] {
        color: #00ffcc !important;
    }
    section[data-testid="stMain"] div[data-testid="stMarkdownContainer"] p {
        color: #e0e0e0;
    }
    section[data-testid="stMain"] div[data-testid="stWidgetLabel"] p {
        color: #e0e0e0;
    }
    section[data-testid="stMain"] p {
        color: #e0e0e0;
    }
</style>
""", unsafe_allow_html=True)

st.title("VeriHash Node Prime")
st.markdown("*Decentralized Proof-of-Work Protocol / Phase 6 Dashboard*")

# 2. Left Sidebar (Identity & Genesis)
with st.sidebar:
    st.header("Identity & Genesis")
    st.markdown("---")
    
    identity_file = "node_identity.json"
    pub_key = None
    if os.path.exists(identity_file):
        try:
            with open(identity_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                pub_key = data.get("public_key")
        except Exception as e:
            st.error(f"Identity Corruption: {e}")
            
    if pub_key:
        st.markdown("**Node Public Key (DID):**")
        st.code(f"did:key:ed25519:{pub_key}", language="text")
    else:
        st.error("⚠️ Identity Not Found. Please ensure `node_identity.json` exists.")
        
    st.markdown("---")
    st.info("🚨 **Physical Watchdog must be running in a separate terminal.**")

    st.markdown("---")
    with st.expander("⚙️ System Settings", expanded=False):
        cfg = config_manager.load_config()
        
        new_dir = st.text_input("Watchdog Target Directory", value=cfg.get("watchdog_target_dir", "./test_workspace"))
        
        mode_options = ["Local (Ollama)", "Cloud (OpenAI-Compatible API)"]
        current_mode_idx = 0 if cfg.get("ai_mode", "local") == "local" else 1
        new_mode_label = st.radio("AI Engine Mode", mode_options, index=current_mode_idx)
        new_mode = "local" if new_mode_label == mode_options[0] else "cloud"
        
        new_local_model = cfg.get("local_model_name", "phi3")
        new_cloud_url = cfg.get("cloud_base_url", "https://api.deepseek.com/chat/completions")
        new_cloud_model = cfg.get("cloud_model_name", "deepseek-chat")
        new_cloud_key = cfg.get("cloud_api_key", "")
        
        if new_mode == "local":
            new_local_model = st.text_input("Local Model Name", value=new_local_model)
        else:
            new_cloud_url = st.text_input("Cloud Base URL", value=new_cloud_url)
            new_cloud_model = st.text_input("Cloud Model Name", value=new_cloud_model)
            new_cloud_key = st.text_input("Cloud API Key", value=new_cloud_key, type="password")
            
        if st.button("Save Settings", use_container_width=True):
            cfg["watchdog_target_dir"] = new_dir
            cfg["ai_mode"] = new_mode
            cfg["local_model_name"] = new_local_model
            cfg["cloud_base_url"] = new_cloud_url
            cfg["cloud_model_name"] = new_cloud_model
            cfg["cloud_api_key"] = new_cloud_key
            
            if config_manager.save_config(cfg):
                st.success("Settings saved successfully!")
            else:
                st.error("Failed to save settings.")

tab1, tab2, tab3 = st.tabs(["⚡ Forge Credential", "📜 Time Machine", "🃏 Showcase Card"])

with tab1:
    # 3. Main Interface - Upper (Hash Chain Explorer)
    st.header("Hash Chain Explorer")

    # Fetch latest 500 records to provide a broad history for grouping
    records = oracle_engine.get_latest_snapshots(limit=500)

    if not records:
        st.warning("Ledger database (`proof_of_work.db`) not found or inaccessible. Awaiting Genesis Block.")
    else:
        # Phase 8.2.3: Read high-water mark from config
        config = config_manager.load_config()
        watermark_id = config.get("last_minted_snapshot_id", 0)
        
        # Auto-recovery: If the user deleted the database, the max ID will drop. 
        # We must reset the watermark so new files don't stay "Minted" forever.
        max_db_id = max((r.get("id", 0) for r in records), default=0)
        if watermark_id > max_db_id:
            watermark_id = 0
            config["last_minted_snapshot_id"] = 0
            config_manager.save_config(config)

        df_data = []
        
        # Group records by File Path
        file_groups = {}
        for r in records:
            fpath = r.get("file_path", "")
            if not fpath:
                continue
            if fpath not in file_groups:
                file_groups[fpath] = []
            file_groups[fpath].append(r)
            
        for fpath, group in file_groups.items():
            dir_name = os.path.dirname(fpath) or "/"
            file_name = os.path.basename(fpath)

            # Records are DESC ordered, so group[0] is the latest modification
            latest_record = group[0]
            dt = datetime.datetime.fromtimestamp(latest_record['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            
            # High-Water Mark Check: File is virgin if ANY of its updates are after the mark
            is_virgin = any(r["id"] > watermark_id for r in group)
            
            df_row = {
                "[✔️ Select]": is_virgin,
                "Status": "🆕 Virgin" if is_virgin else "✅ Minted",
                "Directory": dir_name,
                "File Name": file_name,
                "Revisions": len(group),
                "Latest Update": dt,
                "File Path": fpath,
                "Current Hash": latest_record["current_hash"]
            }
            df_data.append(df_row)

        df = pd.DataFrame(df_data)
        
        # Sort data by Directory and Latest Update to cluster context logically
        df = df.sort_values(by=["Directory", "Latest Update"], ascending=[True, False])

        all_dirs = df["Directory"].unique().tolist()
        
        # --- Advanced Batch Selection Tools ---
        if "editor_key" not in st.session_state:
            st.session_state.editor_key = 0
            st.session_state.select_mode = "default"

        st.markdown("**🧹 Batch Selection Tools**")
        col_btn1, col_btn2, col_btn3 = st.columns(3)
        with col_btn1:
            if st.button("☑️ Select All", use_container_width=True):
                st.session_state.select_mode = "all"
                st.session_state.editor_key += 1
        with col_btn2:
            if st.button("🔲 Deselect All", use_container_width=True):
                st.session_state.select_mode = "none"
                st.session_state.editor_key += 1
        with col_btn3:
            if st.button("🆕 Virgin Only", use_container_width=True):
                st.session_state.select_mode = "default"
                st.session_state.editor_key += 1

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            included_dirs = st.multiselect("📁 Focus Directories (Include Only)", options=all_dirs, help="If selected, ONLY files in these directories will be checked.")
        with col_f2:
            excluded_dirs = st.multiselect("🚫 Exclude Directories", options=all_dirs, help="Select to automatically uncheck corresponding directories.")

        # Apply Global Modes
        mode = st.session_state.get("select_mode", "default")
        if mode == "all":
            df["[✔️ Select]"] = True
        elif mode == "none":
            df["[✔️ Select]"] = False
        else:
            # "default" or "Virgin Only" state: re-evaluate based on the virgin status
            df["[✔️ Select]"] = df["Status"] == "🆕 Virgin"
        if included_dirs:
            df["[✔️ Select]"] = df["Directory"].isin(included_dirs)
            
        if excluded_dirs:
            df.loc[df["Directory"].isin(excluded_dirs), "[✔️ Select]"] = False

        # Interactive Editable Table
        edited_df = st.data_editor(
            df,
            key=f"data_editor_{st.session_state.editor_key}",
            column_config={
                "[✔️ Select]": st.column_config.CheckboxColumn(
                    "[✔️ Select]",
                    help="Select this file to include in AI Context",
                    default=True,
                ),
                "Directory": None
            },
            disabled=["Status", "Directory", "File Name", "Revisions", "Latest Update", "File Path", "Current Hash"],
            hide_index=True,
            use_container_width=True
        )

    # 4. Main Interface - Lower (Oracle Minting Station)
    st.markdown("---")
    st.header("Oracle Minting Station")

    if st.button("⚡ Mint Session Credential", use_container_width=True):
        with st.spinner("Initiating Oracle Engine... Synchronizing Hash Chain and Synthesizing AI Insights..."):
            try:
                if not records:
                    st.error("Data void detected. Cannot mint credential without recent file snapshots.")
                else:
                    # Filter records based on UI selection
                    selected_paths = edited_df[edited_df["[✔️ Select]"] == True]["File Path"].tolist()
                    
                    if not selected_paths:
                        st.error("No files selected. Context isolation requires at least one file.")
                    elif len(selected_paths) > 20:
                        st.error(f"Selection limit exceeded. You selected {len(selected_paths)} files, but the maximum is 20 for optimal AI evaluation. Please refine your selection.")
                    else:
                        # Pass ALL snapshot records belonging to the selected files
                        selected_records = [r for r in records if r.get("file_path") in selected_paths]
                        
                        vc = oracle_engine.mint_session_credential(selected_records)
                        st.success(f"Session Verifiable Credential forged with {len(selected_paths)} files successfully!")
                        st.json(vc)
            except Exception as e:
                st.error(f"Oracle Minting Sequence Failed: {e}")

with tab2:
    st.header("📜 Time Machine Archive")
    
    search_query = st.text_input("🔍 Search History (Keyword in Insight, Skills, or Project)", "")
    
    try:
        with sqlite3.connect("proof_of_work.db") as conn:
            conn.row_factory = sqlite3.Row
            # Only query active credentials (status = 1)
            query = "SELECT vc_id, timestamp, project_context, ai_insight, skill_tags, file_paths FROM session_credentials WHERE status = 1 ORDER BY timestamp DESC"
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            
            if rows:
                archive_data = []
                for row in rows:
                    dt = datetime.datetime.fromtimestamp(row["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
                    try:
                        fp_list = json.loads(row["file_paths"])
                        fp_str = ", ".join(fp_list) if isinstance(fp_list, list) else str(fp_list)
                    except:
                        fp_str = str(row["file_paths"])
                        
                    archive_data.append({
                        "Time": dt,
                        "Project": row["project_context"],
                        "AI Insight": row["ai_insight"],
                        "Skill Tree": row["skill_tags"],
                        "File Paths": fp_str
                    })
                
                df_archive = pd.DataFrame(archive_data)
                
                if search_query:
                    search_query_lower = search_query.lower()
                    mask = (
                        df_archive["AI Insight"].str.lower().str.contains(search_query_lower) |
                        df_archive["Skill Tree"].str.lower().str.contains(search_query_lower) |
                        df_archive["Project"].str.lower().str.contains(search_query_lower)
                    )
                    df_archive = df_archive[mask]
                
                st.dataframe(
                    df_archive,
                    column_config={
                        "Time": st.column_config.TextColumn("Time"),
                        "Project": "Project Context",
                        "AI Insight": st.column_config.TextColumn("AI Insight", width="large"),
                        "Skill Tree": "Skill Tags",
                        "File Paths": "Involved Files"
                    },
                    hide_index=True,
                    use_container_width=True
                )
                
                # Phase 3.5: Burn Console
                st.markdown("---")
                with st.expander("🔥 Burn Console"):
                    st.error("⚠️ **WARNING: Incinerating a credential will permanently remove it from your public showcase. The underlying physical PoW blocks remain crystallized on the hash chain.**")
                    
                    # Create a mapping of readable labels to VC IDs
                    burn_options = {f"{datetime.datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S')} | {row['project_context']}": row['vc_id'] for row in rows}
                    
                    selected_burn_label = st.selectbox("Select Credential to Incinerate", list(burn_options.keys()))
                    
                    if st.button("🔥 Burn Selected Credential", type="primary", use_container_width=True):
                        if selected_burn_label:
                            target_vc_id = burn_options[selected_burn_label]
                            if database.burn_credential(target_vc_id):
                                st.success("Credential incinerated. It will no longer appear in your public showcase.")
                                time.sleep(1) # Brief pause for user to read message
                                st.rerun()
                            else:
                                st.error("Failed to incinerate credential.")
                        
            else:
                st.info("No credentials archived yet. Start forging in the workspace!")
    except sqlite3.OperationalError:
        st.warning("Archive database not initialized or missing.")

with tab3:
    st.header("🃏 Cyberpunk Showcase Card")
    st.markdown("Select an archived credential to render your cyberpunk-style shareable PoW card.")

    try:
        with sqlite3.connect("proof_of_work.db") as conn:
            conn.row_factory = sqlite3.Row
            # Phase 3.5: Only query active credentials
            query = "SELECT vc_id, timestamp, project_context, ai_insight, skill_tags, full_vc_json FROM session_credentials WHERE status = 1 ORDER BY timestamp DESC"
            cursor = conn.execute(query)
            rows = cursor.fetchall()
            
            if not rows:
                st.info("No credentials archived yet. Start forging to generate your showcase cards!")
            else:
                # Format dropdown options
                options = {f"{datetime.datetime.fromtimestamp(row['timestamp']).strftime('%Y-%m-%d %H:%M:%S')} | {row['project_context']}": dict(row) for row in rows}
                
                selected_label = st.selectbox("Select History Record", list(options.keys()))
                
                if selected_label:
                    selected_data = options[selected_label]
                    
                    # Extract values
                    dt_str = datetime.datetime.fromtimestamp(selected_data["timestamp"]).strftime('%Y-%m-%d %H:%M:%S')
                    project = selected_data["project_context"]
                    
                    # Convert newlines to <br> for HTML rendering to prevent markdown code block wrapping
                    insight = selected_data["ai_insight"].replace('\n', '<br>')
                    vc_id = selected_data["vc_id"]
                    
                    # Process skill tags (handling historical differences like asterisks or newlines)
                    raw_tags = selected_data["skill_tags"]
                    if raw_tags:
                        clean_tags = raw_tags.replace('*', ',').replace('\n', ',')
                        tags = [t.strip() for t in clean_tags.split(',') if t.strip()]
                    else:
                        tags = []
                    
                    # Parse signature
                    try:
                        vc_json = json.loads(selected_data["full_vc_json"])
                        sig_val = vc_json.get("proof", {}).get("digital_signature", "N/A")
                    except:
                        sig_val = "N/A"
                        
                    # Build badges HTML (GitHub Topic style)
                    badges_html = "".join([f'<span style="background-color: #1f2937; border: 1px solid #00ffcc; color: #00ffcc; padding: 4px 10px; border-radius: 20px; font-size: 0.8em; margin-right: 8px; margin-bottom: 8px; display: inline-block; white-space: nowrap;">{tag}</span>' for tag in tags if tag])
                    
                    # Construct Cyber Card HTML on a single line to completely prevent Streamlit Markdown misinterpreting as a code block
                    cyber_card_html = (
                        f'<div style="display: flex; justify-content: center; padding: 20px;">'
                        f'<div style="background-color: #0d1117; border: 2px solid #00ffcc; border-radius: 12px; padding: 25px; box-shadow: 0 0 20px rgba(0, 255, 204, 0.4); font-family: \'Courier New\', Courier, monospace; color: #e0e0e0; max-width: 650px; width: 100%;">'
                        f'<!-- Header -->'
                        f'<div style="border-bottom: 1px dashed #00ffcc; padding-bottom: 12px; margin-bottom: 18px; display: flex; justify-content: space-between; align-items: flex-end;">'
                        f'<div style="color: #00ffcc; font-weight: 900; font-size: 1.3rem; letter-spacing: 1px; text-shadow: 0 0 5px #00ffcc;">⚡ VeriHash PoW</div>'
                        f'<div style="font-size: 0.85rem; opacity: 0.7;">{dt_str}</div>'
                        f'</div>'
                        f'<!-- Main Body -->'
                        f'<div style="margin-bottom: 20px;">'
                        f'<div style="font-size: 1.4rem; font-weight: bold; margin-bottom: 12px; color: #ffffff; word-break: break-word; overflow-wrap: anywhere;">{project}</div>'
                        f'<div style="background: rgba(0, 255, 204, 0.05); padding: 15px; border-left: 4px solid #00ffcc; font-size: 0.95rem; line-height: 1.5; white-space: pre-wrap;">{insight}</div>'
                        f'</div>'
                        f'<!-- Badges -->'
                        f'<div style="margin-bottom: 25px; display: flex; flex-wrap: wrap;">{badges_html}</div>'
                        f'<!-- Crypto Footer Layer -->'
                        f'<div style="border-top: 1px dashed #333; padding-top: 15px; font-size: 0.65rem; color: #666; word-break: break-all; line-height: 1.4;">'
                        f'<div style="margin-bottom: 4px;"><strong style="color: #888;">VC ID:</strong> {vc_id}</div>'
                        f'<div><strong style="color: #888;">SIGNATURE/HASH:</strong> {sig_val}</div>'
                        f'</div>'
                        f'</div>'
                        f'</div>'
                    )
                    
                    st.markdown(cyber_card_html, unsafe_allow_html=True)
                    
    except sqlite3.OperationalError:
        st.warning("Archive database not initialized or missing.")
