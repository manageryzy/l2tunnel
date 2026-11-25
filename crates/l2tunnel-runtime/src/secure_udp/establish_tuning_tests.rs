//! Live-tuning proposal through the real setup stream
//! (docs/modules/live-tuning.md, LT-02).

use super::*;
use l2tunnel::live_tuning::Refusal;

type Outcome = Result<EstablishedState<NoRaw>, Error>;

async fn tuned_pair(client_tuning: Tuning<'_>, server_tuning: Tuning<'_>) -> (Outcome, Outcome) {
    let (client, server, path) = pair().await;
    let client_cfg = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Initiator,
        hs::Profile::Ik,
    );
    let server_cfg = config(
        path,
        cover::Appearance::QuicLike,
        hs::Role::Responder,
        hs::Profile::Ik,
    );
    let origin = Instant::now();
    let end = origin + Duration::from_secs(2);
    let mut admission = ServerAdmission::new(
        server_cfg,
        peers(),
        gate::Secret::new([1; 32]),
        gate::Secret::new([2; 32]),
        origin,
    )
    .expect("admission");
    let mut client_entropy = Entropy::new(9);
    let mut server_entropy = Entropy::new(19);
    let mut client_observe = |_| {};
    let mut server_observe = |_| {};
    let mut client_report = Reporter::new(&mut client_observe);
    let mut server_report = Reporter::new(&mut server_observe);
    tokio::join!(
        connect_inner(
            SocketBacking::<NoRaw>::Udp(client),
            client_cfg,
            identity(hs::Role::Initiator, hs::Profile::Ik),
            gate::Secret::new([1; 32]),
            end,
            &mut client_entropy,
            &mut client_report,
            None,
            client_tuning,
        ),
        accept_inner(
            SocketBacking::<NoRaw>::Udp(server),
            identity(hs::Role::Responder, hs::Profile::Ik),
            &mut admission,
            end,
            &mut server_entropy,
            &mut server_report,
            None,
            server_tuning,
        )
    )
}

fn proposal() -> Vec<u8> {
    l2tunnel::live_tuning::Choices {
        repair: vec![l2tunnel::live_tuning::Repair::Off],
        device_mtu: vec![1280],
        path_mtu: vec![1350],
    }
    .encode()
    .expect("encode")
}

#[tokio::test]
async fn accepted_proposal_reaches_the_judge_and_binds_both_ends() {
    // A small real proposal, and the largest one, which spans four
    // bootstrap ARQ sources of 100 bytes.
    for bytes in [proposal(), vec![0x5A; hs::MAX_INITIATION_PAYLOAD]] {
        let mut seen = Vec::new();
        let mut judge = |carried: &[u8]| -> Result<[u8; 32], Refusal> {
            seen.push(carried.to_vec());
            Ok([9; 32])
        };
        let (client, server) = tuned_pair(
            Tuning::Propose {
                proposal: &bytes,
                context: [9; 32],
            },
            Tuning::Judge(&mut judge),
        )
        .await;
        let (Ok(client), Ok(server)) = (&client, &server) else {
            panic!(
                "client={:?} server={:?}",
                client.as_ref().err(),
                server.as_ref().err()
            );
        };
        assert_eq!(client.binding, server.binding);
        assert_eq!(seen, [bytes]);
    }
}

#[tokio::test]
async fn differing_derived_catalogs_never_complete() {
    let bytes = proposal();
    let mut judge = |_: &[u8]| -> Result<[u8; 32], Refusal> { Ok([8; 32]) };
    let (client, server) = tuned_pair(
        Tuning::Propose {
            proposal: &bytes,
            context: [9; 32],
        },
        Tuning::Judge(&mut judge),
    )
    .await;
    assert!(
        matches!(client, Err(Error::Noise(hs::Error::Authentication))),
        "client={:?}",
        client.as_ref().err()
    );
    assert!(server.is_err());
}

#[tokio::test]
async fn refused_and_unoffered_proposals_end_both_sides_with_the_exact_reason() {
    let bytes = proposal();
    let mut judge = |_: &[u8]| -> Result<[u8; 32], Refusal> { Err(Refusal::RepairLimit) };
    let (client, server) = tuned_pair(
        Tuning::Propose {
            proposal: &bytes,
            context: [9; 32],
        },
        Tuning::Judge(&mut judge),
    )
    .await;
    assert!(
        matches!(client, Err(Error::Tuning(Refusal::RepairLimit))),
        "client={:?}",
        client.as_ref().err()
    );
    assert!(
        matches!(server, Err(Error::Tuning(Refusal::RepairLimit))),
        "server={:?}",
        server.as_ref().err()
    );

    let (client, server) = tuned_pair(
        Tuning::Propose {
            proposal: &bytes,
            context: [9; 32],
        },
        Tuning::Off,
    )
    .await;
    assert!(
        matches!(client, Err(Error::Tuning(Refusal::NotOffered))),
        "client={:?}",
        client.as_ref().err()
    );
    assert!(
        matches!(server, Err(Error::Tuning(Refusal::NotOffered))),
        "server={:?}",
        server.as_ref().err()
    );
}

#[tokio::test]
async fn a_judging_server_still_takes_a_plain_client_and_roles_are_checked() {
    let mut called = false;
    let mut judge = |_: &[u8]| -> Result<[u8; 32], Refusal> {
        called = true;
        Ok([9; 32])
    };
    let (client, server) = tuned_pair(Tuning::Off, Tuning::Judge(&mut judge)).await;
    assert!(client.is_ok() && server.is_ok());
    assert!(!called);

    let mut judge = |_: &[u8]| -> Result<[u8; 32], Refusal> { Ok([9; 32]) };
    let (client, _) = tuned_pair(Tuning::Judge(&mut judge), Tuning::Off).await;
    assert!(matches!(
        client,
        Err(Error::Configuration("live-tuning role"))
    ));
    let (client, _) = tuned_pair(
        Tuning::Propose {
            proposal: &[],
            context: [9; 32],
        },
        Tuning::Off,
    )
    .await;
    assert!(matches!(
        client,
        Err(Error::Configuration("empty live-tuning proposal"))
    ));
}
