// ChatView.swift — SwiftUI chat surface over ChatController:
// conversation list with unread badges, history, compose, poll, contacts.
import SwiftUI
import DtnModels
import DtnShell

struct ChatView: View {
    @EnvironmentObject private var controller: ChatController
    @State private var draft = ""
    @State private var recipient = ""
    @State private var showAddContact = false

    var body: some View {
        NavigationStack {
            List {
                if let peer = controller.selectedPeer {
                    Section("Conversation \(peer)") {
                        ForEach(controller.history, id: \.id) { message in
                            MessageRow(message: message)
                        }
                    }
                }
                Section("Conversations") {
                    if controller.conversations.isEmpty {
                        Text("No conversations yet")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(controller.conversations, id: \.peer) { convo in
                        Button {
                            controller.select(peer: convo.peer)
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(convo.peer).bold()
                                    Text(convo.lastBody)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .lineLimit(1)
                                }
                                Spacer()
                                if convo.unread > 0 {
                                    Text("\(convo.unread)")
                                        .font(.caption2.bold())
                                        .padding(6)
                                        .background(Capsule().fill(.red))
                                        .foregroundStyle(.white)
                                }
                            }
                        }
                    }
                }
            }
            .navigationTitle(controller.eid.isEmpty ? "DTN-Link" : controller.eid)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        do { try controller.poll() } catch {
                            controller.statusText = "poll failed: \(error)"
                        }
                    } label: { Image(systemName: "arrow.triangle.2.circlepath") }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button { showAddContact = true } label: {
                        Image(systemName: "person.badge.plus")
                    }
                }
            }
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 4) {
                    if !controller.statusText.isEmpty {
                        Text(controller.statusText)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    HStack {
                        TextField("alias or dtn://eid", text: $recipient)
                            .textFieldStyle(.roundedBorder)
                            .frame(maxWidth: 140)
                        TextField("Message", text: $draft)
                            .textFieldStyle(.roundedBorder)
                            .onSubmit(send)
                        Button("Send", action: send)
                            .disabled(draft.isEmpty || recipient.isEmpty)
                    }.padding(8)
                }
                .background(.bar)
            }
            .sheet(isPresented: $showAddContact) {
                AddContactView(controller: controller)
            }
        }
    }

    private func send() {
        guard !draft.isEmpty, !recipient.isEmpty else { return }
        do {
            if try controller.send(to: recipient, body: draft) >= 0 {
                draft = ""
            }
        } catch {
            controller.statusText = "send failed: \(error)"
        }
    }
}

struct MessageRow: View {
    let message: Message

    var body: some View {
        HStack {
            if message.direction == .outbound { Spacer(minLength: 40) }
            Text(message.body)
                .padding(8)
                .background(message.direction == .outbound
                            ? AnyShapeStyle(Color.accentColor.opacity(0.25))
                            : AnyShapeStyle(Color.secondary.opacity(0.15)))
                .clipShape(RoundedRectangle(cornerRadius: 12))
            if message.direction == .inbound { Spacer(minLength: 40) }
        }
    }
}

struct AddContactView: View {
    @Environment(\.dismiss) private var dismiss
    let controller: ChatController
    @State private var alias = ""
    @State private var eid = ""

    var body: some View {
        NavigationStack {
            Form {
                TextField("Alias", text: $alias)
                TextField("EID (dtn://name or ipn:n.s)", text: $eid)
            }
            .navigationTitle("Add contact")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        if let status = tryAdd() { controller.statusText = status }
                        dismiss()
                    }
                    .disabled(alias.isEmpty || eid.isEmpty)
                }
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }

    private func tryAdd() -> String? {
        guard !alias.isEmpty, !eid.isEmpty else { return nil }
        do {
            let created = try controller.addContact(alias: alias, eid: eid)
            return created ? "contact \(alias) created" : "contact \(alias) updated"
        } catch {
            return "add contact failed: \(error)"
        }
    }
}
