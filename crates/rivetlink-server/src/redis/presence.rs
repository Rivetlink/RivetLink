//! Device presence tracking via Redis keys with TTL.

use redis::AsyncCommands;
use uuid::Uuid;

use crate::error::ServerResult;

const PRESENCE_PREFIX: &str = "presence:";
const PRESENCE_TTL_SECS: u64 = 30;

/// Mark device online by setting Redis key with TTL.
pub async fn set_online(
    conn: &mut redis::aio::MultiplexedConnection,
    device_id: Uuid,
) -> ServerResult<()> {
    let key = format!("{PRESENCE_PREFIX}{device_id}");
    let () = conn.set_ex(&key, "1", PRESENCE_TTL_SECS).await?;
    Ok(())
}

/// Extend presence TTL to keep device online.
pub async fn refresh_presence(
    conn: &mut redis::aio::MultiplexedConnection,
    device_id: Uuid,
) -> ServerResult<()> {
    let key = format!("{PRESENCE_PREFIX}{device_id}");
    #[allow(clippy::cast_possible_wrap)]
    let () = conn.expire(&key, PRESENCE_TTL_SECS as i64).await?;
    Ok(())
}

/// Mark device offline by deleting Redis key.
pub async fn set_offline(
    conn: &mut redis::aio::MultiplexedConnection,
    device_id: Uuid,
) -> ServerResult<()> {
    let key = format!("{PRESENCE_PREFIX}{device_id}");
    let () = conn.del(&key).await?;
    Ok(())
}

/// Check if device is online (presence key exists in Redis).
pub async fn is_online(
    conn: &mut redis::aio::MultiplexedConnection,
    device_id: Uuid,
) -> ServerResult<bool> {
    let key = format!("{PRESENCE_PREFIX}{device_id}");
    let exists: bool = conn.exists(&key).await?;
    Ok(exists)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn get_redis_conn() -> Option<redis::aio::MultiplexedConnection> {
        let client = redis::Client::open("redis://127.0.0.1:6379").ok()?;
        client.get_multiplexed_async_connection().await.ok()
    }

    #[tokio::test]
    async fn presence_set_and_check() {
        let Some(mut conn) = get_redis_conn().await else {
            eprintln!("skipping: redis not available");
            return;
        };

        let device_id = Uuid::now_v7();

        set_online(&mut conn, device_id).await.unwrap();
        assert!(is_online(&mut conn, device_id).await.unwrap());

        set_offline(&mut conn, device_id).await.unwrap();
        assert!(!is_online(&mut conn, device_id).await.unwrap());
    }

    #[tokio::test]
    async fn presence_nonexistent_device_is_offline() {
        let Some(mut conn) = get_redis_conn().await else {
            eprintln!("skipping: redis not available");
            return;
        };

        let device_id = Uuid::now_v7();
        assert!(!is_online(&mut conn, device_id).await.unwrap());
    }

    #[tokio::test]
    async fn presence_refresh_extends_ttl() {
        let Some(mut conn) = get_redis_conn().await else {
            eprintln!("skipping: redis not available");
            return;
        };

        let device_id = Uuid::now_v7();
        set_online(&mut conn, device_id).await.unwrap();
        refresh_presence(&mut conn, device_id).await.unwrap();
        assert!(is_online(&mut conn, device_id).await.unwrap());
    }
}
