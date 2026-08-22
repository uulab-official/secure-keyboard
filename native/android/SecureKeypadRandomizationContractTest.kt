package com.uulab.securekeypad

import java.util.Random

private fun input(id: String): SecureKeySpec = SecureKeySpec(id, id, SecureKeyRole.INPUT)

private fun action(id: String, role: SecureKeyRole): SecureKeySpec = SecureKeySpec(id, id, role)

fun main() {
    val rows = listOf(
        listOf(input("digit-1"), action("backspace", SecureKeyRole.BACKSPACE), input("digit-2")),
        listOf(input("digit-3"), action("submit", SecureKeyRole.SUBMIT), input("digit-4")),
    )

    check(secureKeypadPresentationRows(rows, randomizeInputKeys = false, random = Random(7)) === rows)

    val randomized = secureKeypadPresentationRows(rows, randomizeInputKeys = true, random = Random(7))
    check(randomized.map { it.size } == rows.map { it.size })
    check(randomized[0][1].id == "backspace")
    check(randomized[1][1].id == "submit")
    check(randomized.flatten().filter { it.role == SecureKeyRole.INPUT }.map { it.id }.toSet() == setOf(
        "digit-1",
        "digit-2",
        "digit-3",
        "digit-4",
    ))
    check(randomized.flatten().count { it.role == SecureKeyRole.INPUT } == 4)

    val onlyActions = listOf(
        listOf(action("clear", SecureKeyRole.CLEAR), action("cancel", SecureKeyRole.CANCEL)),
    )
    val actionOnlyPresentation = secureKeypadPresentationRows(
        onlyActions,
        randomizeInputKeys = true,
        random = Random(7),
    )
    check(actionOnlyPresentation == onlyActions)
}
