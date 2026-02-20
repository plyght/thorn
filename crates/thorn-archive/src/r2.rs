use s3::bucket::Bucket;
use s3::creds::Credentials;
use s3::Region;
use thorn_core::{ThornError, ThornResult};
use tracing::info;

pub struct R2Archive {
    bucket: Box<Bucket>,
}

impl R2Archive {
    pub fn new(
        bucket_name: &str,
        account_id: &str,
        access_key: &str,
        secret_key: &str,
    ) -> ThornResult<Self> {
        let region = Region::R2 {
            account_id: account_id.to_string(),
        };
        let credentials = Credentials::new(Some(access_key), Some(secret_key), None, None, None)
            .map_err(|e| ThornError::Archive(e.to_string()))?;
        let bucket = Bucket::new(bucket_name, region, credentials)
            .map_err(|e| ThornError::Archive(e.to_string()))?
            .with_path_style();
        Ok(Self { bucket })
    }

    pub async fn upload(&self, key: &str, data: &[u8], content_type: &str) -> ThornResult<()> {
        self.bucket
            .put_object_with_content_type(key, data, content_type)
            .await
            .map_err(|e| ThornError::Archive(e.to_string()))?;
        info!(key = %key, size = data.len(), "archived to R2");
        Ok(())
    }

    pub async fn upload_json(&self, key: &str, value: &serde_json::Value) -> ThornResult<()> {
        let data = serde_json::to_vec_pretty(value).map_err(|e| ThornError::Archive(e.to_string()))?;
        self.upload(key, &data, "application/json").await
    }

    pub async fn download(&self, key: &str) -> ThornResult<Vec<u8>> {
        let resp = self
            .bucket
            .get_object(key)
            .await
            .map_err(|e| ThornError::Archive(e.to_string()))?;
        Ok(resp.to_vec())
    }

    pub async fn archive_honeypot_hits(&self, hits_json: &serde_json::Value) -> ThornResult<()> {
        let key = format!(
            "honeypot/{}.json",
            chrono::Utc::now().format("%Y/%m/%d/%H%M%S")
        );
        self.upload_json(&key, hits_json).await
    }

    pub async fn archive_scan_results(&self, scans_json: &serde_json::Value) -> ThornResult<()> {
        let key = format!(
            "scans/{}.json",
            chrono::Utc::now().format("%Y/%m/%d/%H%M%S")
        );
        self.upload_json(&key, scans_json).await
    }

    pub async fn archive_evidence(&self, label: &str, data: &[u8]) -> ThornResult<()> {
        let key = format!(
            "evidence/{}/{}.bin",
            chrono::Utc::now().format("%Y/%m/%d"),
            label,
        );
        self.upload(&key, data, "application/octet-stream").await
    }
}
