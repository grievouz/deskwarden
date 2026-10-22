import Foundation
import Testing
@testable import DeskwardenKit

struct ApprovalTests {
    /// Counts prompts and answers them all the same way.
    final class FakePrompt: @unchecked Sendable {
        private let lock = NSLock()
        private var _count = 0
        let answer: Bool

        init(answer: Bool = true) {
            self.answer = answer
        }

        var count: Int { lock.withLock { _count } }

        var prompt: TouchIDApprover.Prompt {
            { [self] _ in
                lock.withLock { _count += 1 }
                return answer
            }
        }
    }

    func request(app: String = "app", connection: UUID = UUID(), scope: String? = nil, remember: Bool = true) -> ApprovalRequest {
        ApprovalRequest(applicationId: app, applicationName: app, connectionId: connection, client: nil, action: "read Item", scope: scope, remember: remember)
    }

    @Test func everyRequestPromptsEachTime() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .everyRequest, prompt: fake.prompt)
        let connection = UUID()
        for _ in 0..<3 {
            #expect(await approver.approve(request(connection: connection)))
        }
        #expect(fake.count == 3)
    }

    @Test func firstRequestPromptsOncePerApplicationUntilLocked() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .firstRequest, prompt: fake.prompt)
        // Separate connections, like one ssh or varlock run after another.
        _ = await approver.approve(request(app: "a"))
        _ = await approver.approve(request(app: "a"))
        #expect(fake.count == 1)
        _ = await approver.approve(request(app: "b"))
        #expect(fake.count == 2)
        // Locking forgets them.
        await approver.forgetApprovals()
        _ = await approver.approve(request(app: "a"))
        #expect(fake.count == 3)
    }

    @Test func intervalPromptsOncePerApplication() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .interval(.seconds(300)), prompt: fake.prompt)
        _ = await approver.approve(request(app: "a"))
        _ = await approver.approve(request(app: "a"))
        #expect(fake.count == 1)
        _ = await approver.approve(request(app: "b"))
        #expect(fake.count == 2)
    }

    @Test func expiredIntervalPromptsAgain() async throws {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .interval(.milliseconds(10)), prompt: fake.prompt)
        _ = await approver.approve(request())
        try await Task.sleep(for: .milliseconds(20))
        _ = await approver.approve(request())
        #expect(fake.count == 2)
    }

    @Test func neverDoesNotPrompt() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .never, prompt: fake.prompt)
        #expect(await approver.approve(request()))
        #expect(fake.count == 0)
    }

    @Test func deniedPromptsAreNotRemembered() async {
        let fake = FakePrompt(answer: false)
        let approver = TouchIDApprover(policy: .interval(.seconds(300)), prompt: fake.prompt)
        #expect(await !approver.approve(request()))
        #expect(await !approver.approve(request()))
        #expect(fake.count == 2)
    }

    @Test func concurrentRequestsShareOnePrompt() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .firstRequest, prompt: fake.prompt)
        let connection = UUID()
        await withTaskGroup(of: Void.self) { group in
            for _ in 0..<10 {
                group.addTask { _ = await approver.approve(request(connection: connection)) }
            }
        }
        #expect(fake.count == 1)
    }

    @Test func forgettingApprovalsPromptsAgain() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .interval(.seconds(300)), prompt: fake.prompt)
        _ = await approver.approve(request())
        await approver.forgetApprovals()
        _ = await approver.approve(request())
        #expect(fake.count == 2)
    }

    @Test func recordedUnlockCountsForTheApplication() async {
        let fake = FakePrompt()
        let first = TouchIDApprover(policy: .firstRequest, prompt: fake.prompt)
        await first.record(request(app: "a"))
        #expect(await first.approve(request(app: "a")))
        let interval = TouchIDApprover(policy: .interval(.seconds(300)), prompt: fake.prompt)
        await interval.record(request(app: "a"))
        #expect(await interval.approve(request(app: "a")))
        #expect(fake.count == 0)
    }

    @Test func recordedUnlockDoesNotSkipEveryRequest() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .everyRequest, prompt: fake.prompt)
        let connection = UUID()
        await approver.record(request(connection: connection))
        _ = await approver.approve(request(connection: connection))
        #expect(fake.count == 1)
    }

    @Test func approvalsAreRememberedPerScope() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .firstRequest, prompt: fake.prompt)
        _ = await approver.approve(request(scope: "item-1"))
        _ = await approver.approve(request(scope: "item-1"))
        #expect(fake.count == 1)
        _ = await approver.approve(request(scope: "item-2"))
        #expect(fake.count == 2)
        // Another application asking for the same item asks too.
        _ = await approver.approve(request(app: "other", scope: "item-1"))
        #expect(fake.count == 3)
    }

    @Test func unrememberedRequestsAlwaysAsk() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .interval(.seconds(300)), prompt: fake.prompt)
        await approver.record(request(scope: "key@host", remember: false))
        _ = await approver.approve(request(scope: "key@host", remember: false))
        _ = await approver.approve(request(scope: "key@host", remember: false))
        #expect(fake.count == 2)
        // Nor do they count for remembered requests.
        _ = await approver.approve(request(scope: "key@host"))
        #expect(fake.count == 3)
    }

    @Test func neverDoesNotAskForUnrememberedRequests() async {
        let fake = FakePrompt()
        let approver = TouchIDApprover(policy: .never, prompt: fake.prompt)
        #expect(await approver.approve(request(remember: false)))
        #expect(fake.count == 0)
    }

    @Test func reasonNamesApplicationAndProject() {
        let request = ApprovalRequest(
            applicationId: "k",
            applicationName: "varlock",
            connectionId: UUID(),
            client: ClientInfo(name: "something else", pid: 42, cwd: "/Users/me/code/shop"),
            action: "read Infra/Stripe"
        )
        #expect(TouchIDApprover.reason(for: request) == "let varlock in shop read Infra/Stripe")
    }
}
