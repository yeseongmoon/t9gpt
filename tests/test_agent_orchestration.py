            "model": model, "benign": benign, "proof": proof.type if proof else None,
            "avoid": list(avoid or []), "reference_context": reference_context,
        })
        return AgentRunResult(
            engine="claude-loop", returncode=0, timed_out=False, duration_seconds=1.0,
            transcript_path=Path(transcript_path), work_dir=Path(work_dir),
            cost_usd=0.01, session_id="sess-1",
            agent_claimed_success=claim,
            model=model, technique_id=technique.id if technique else None,
            result_label={"technique_id": technique.id if technique else "benign",